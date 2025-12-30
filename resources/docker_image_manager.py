import hashlib
import os
import threading
from pathlib import Path
from typing import Dict, Optional, Tuple

import docker

DEFAULT_REMOTE_IMAGE: str = "cybench/bountyagent:latest"

# Prevent repeated/concurrent pull/build across retries and/or multiple resources in-process
_IMAGE_RESOLVE_LOCK = threading.Lock()
_IMAGE_READY_CACHE: Dict[Tuple[str, str], str] = {}  # (local_tag, platform) -> image_id


def _normalize_arch(arch: str) -> str:
    a = (arch or "").lower()
    # Common daemon variants vs Docker platform arch names
    if a in {"x86_64", "x64", "amd64"}:
        return "amd64"
    if a in {"aarch64", "arm64"}:
        return "arm64"
    return a


def _normalize_platform(platform: str) -> str:
    p = (platform or "").strip()
    if not p:
        return "linux/amd64"
    if "/" not in p:
        # allow passing just arch
        return f"linux/{_normalize_arch(p)}"
    os_name, arch = (p.split("/", 1) + [""])[:2]
    os_name = (os_name or "linux").lower()
    arch = _normalize_arch(arch)
    return f"{os_name}/{arch}"


def get_target_platform(client: docker.DockerClient) -> str:
    """
    Resolve target platform for docker pull/build by docker daemon info (Architecture)
    """

    try:
        info = client.info()
        arch = (info or {}).get("Architecture") or "amd64"
        return _normalize_platform(f"linux/{arch}")
    except Exception:
        return "linux/amd64"


def _get_local_image(client: docker.DockerClient, tag: str):
    try:
        return client.images.get(tag)
    except docker.errors.ImageNotFound:
        return None


def _image_id_still_present(client: docker.DockerClient, image_id: str) -> bool:
    try:
        client.images.get(image_id)
        return True
    except Exception:
        return False


def _image_matches_platform(image, platform: str) -> bool:
    """
    Best-effort platform match using image inspect fields.
    """
    platform = _normalize_platform(platform)
    expected_os, expected_arch = platform.split("/", 1)
    try:
        attrs = getattr(image, "attrs", {}) or {}
        os_name = (attrs.get("Os") or attrs.get("OS") or "").lower()
        arch = _normalize_arch(attrs.get("Architecture") or "")
        if expected_os and os_name and os_name != expected_os:
            return False
        if expected_arch and arch and arch != expected_arch:
            return False
        return True
    except Exception:
        # If we can't reliably determine, don't block usage (but we tried).
        return True


def _pull_remote_image_for_platform(
    client: docker.DockerClient, remote: str, platform: str, logger=None
):
    platform = _normalize_platform(platform)
    if logger:
        logger.debug(f"Attempting to pull Docker image '{remote}' for platform {platform}")
    try:
        # docker-py supports `platform` for pull on newer versions
        try:
            client.images.pull(remote, platform=platform)
        except TypeError:
            client.images.pull(remote)
        return _get_local_image(client, remote)
    except Exception as e:
        if logger:
            logger.warning(
                f"Failed to pull '{remote}' for platform {platform}: {e}. Will fall back to local build."
            )
        return None


def _build_local_image_from_repo_root(
    client: docker.DockerClient,
    local_tag: str,
    repo_root: Path,
    platform: str,
    logger=None,
):
    platform = _normalize_platform(platform)
    dockerfile_path = repo_root / "Dockerfile"
    if not dockerfile_path.exists():
        raise FileNotFoundError(f"Dockerfile not found at repo root: {dockerfile_path}")

    dockerfile_sha = hashlib.sha256(dockerfile_path.read_bytes()).hexdigest()

    # If an existing local image is already labeled with this Dockerfile + platform, reuse it.
    existing = _get_local_image(client, local_tag)
    if existing:
        labels = (
            (getattr(existing, "attrs", {}) or {})
            .get("Config", {})
            .get("Labels", {})
            or {}
        )
        if (
            labels.get("bountybench.dockerfile.sha256") == dockerfile_sha
            and labels.get("bountybench.platform") == platform
            and _image_matches_platform(existing, platform)
        ):
            return existing

    if logger:
        logger.debug(
            f"Building Docker image '{local_tag}' from {dockerfile_path} for platform {platform}"
        )

    build_kwargs = dict(
        path=str(repo_root),
        dockerfile="Dockerfile",
        tag=local_tag,
        rm=True,
        labels={
            "bountybench.dockerfile.sha256": dockerfile_sha,
            "bountybench.platform": platform,
        },
    )
    try:
        image, _logs = client.images.build(platform=platform, **build_kwargs)
    except TypeError:
        image, _logs = client.images.build(**build_kwargs)
    return image


def ensure_image_ready(
    client: docker.DockerClient,
    local_tag: str,
    platform: Optional[str] = None,
    default_remote_image: Optional[str] = DEFAULT_REMOTE_IMAGE,
    repo_root: Optional[Path] = None,
    logger=None,
) -> str:
    """
    Ensure `local_tag` exists locally for the target platform.

    Resolution order:
    - Prefer an existing local `local_tag` that matches the target platform.
    - Else try pulling DEFAULT_REMOTE_IMAGE constrained to the target platform; if successful, tag it as `local_tag`.
    - Else build from `repo_root/Dockerfile` and tag as `local_tag`.

    Returns: resolved image id.
    """
    logger.info(f"Ensuring image {local_tag} is ready...")
    if repo_root is None:
        repo_root = Path(__file__).resolve().parents[1]
    platform = _normalize_platform(platform or get_target_platform(client))
    cache_key = (local_tag, platform)

    with _IMAGE_RESOLVE_LOCK:
        cached_id = _IMAGE_READY_CACHE.get(cache_key)
        if cached_id and _image_id_still_present(client, cached_id):
            return cached_id

        local = _get_local_image(client, local_tag)
        if local and _image_matches_platform(local, platform):
            _IMAGE_READY_CACHE[cache_key] = local.id
            if logger:
                logger.info(
                    f"Using local Docker image '{local_tag}' for platform {platform}: {local.id}"
                )
            return local.id

        pulled = _pull_remote_image_for_platform(client, default_remote_image, platform, logger)
        if pulled and _image_matches_platform(pulled, platform):
            if default_remote_image != local_tag:
                pulled.tag(local_tag)
            _IMAGE_READY_CACHE[cache_key] = pulled.id
            if logger:
                logger.info(
                    f"Using pulled Docker image '{default_remote_image}' tagged as '{local_tag}' for platform {platform}: {pulled.id}"
                )
            return pulled.id

        built = _build_local_image_from_repo_root(client, local_tag, repo_root, platform, logger)
        _IMAGE_READY_CACHE[cache_key] = built.id
        if logger:
            logger.info(
                f"Using locally built Docker image '{local_tag}' for platform {platform}: {built.id}"
            )
        return built.id


