import os
import select
import subprocess
import sys


def run_command(command, work_dir=None, verbose=True):
    """
    Runs a shell command while capturing output in real-time.

    :param command: List of command arguments.
    :param work_dir: Working directory to execute the command in.
    :param verbose: If True, prints stdout/stderr in real time.
    :return: subprocess.CompletedProcess with stdout and stderr as strings.
    """
    print(f"Running command: {' '.join(command)} in work dir: {work_dir}")
    print(f"Environment: {os.environ.copy()}")
    try:
        process = subprocess.Popen(
            command,
            cwd=work_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            universal_newlines=True,
            env=os.environ.copy(),
        )

        stdout_lines = []
        stderr_lines = []

        fds = [process.stdout, process.stderr]
        while process.poll() is None:
            readable, _, _ = select.select(fds, [], [], 0.1)
            for fd in readable:
                line = fd.readline()
                if line:
                    if fd == process.stdout:
                        if verbose:
                            sys.stdout.write(line)
                            sys.stdout.flush()
                        stdout_lines.append(line)
                    else:
                        if verbose:
                            sys.stderr.write(line)
                            sys.stderr.flush()
                        stderr_lines.append(line)

        # Flush remaining lines after process ends
        for fd in fds:
            for line in fd:
                if fd == process.stdout:
                    if verbose:
                        sys.stdout.write(line)
                        sys.stdout.flush()
                    stdout_lines.append(line)
                else:
                    if verbose:
                        sys.stderr.write(line)
                        sys.stderr.flush()
                    stderr_lines.append(line)

        process.stdout.close()
        process.stderr.close()
        process.wait()

        return subprocess.CompletedProcess(
            args=command,
            returncode=process.returncode,
            stdout="".join(stdout_lines),
            stderr="".join(stderr_lines),
        )

    except PermissionError as e:
        print(
            f"Command '{' '.join(command)}' failed with PermissionError {str(e)}"
        )
        if verbose:
            sys.stderr.write(f"Error executing command: {' '.join(command)}\n")
            sys.stderr.flush()
        raise

    except Exception as e:
        print(f"Command '{' '.join(command)}' failed with exception: {e}")
        if hasattr(e, "stdout"):
            print(f"stdout: {e.stdout}")
        if hasattr(e, "stderr"):
            print(f"stderr: {e.stderr}")
        if verbose:
            sys.stderr.write(f"Error executing command: {' '.join(command)}\n")
            sys.stderr.flush()
        raise

if __name__ == "__main__":
    result = run_command(command=["./setup_repo_env.sh"], work_dir="/workspaces/bountybench/bountytasks/LibreChat", verbose=True)
    print(result.stdout)
    print(result.stderr)
    print(result.returncode)