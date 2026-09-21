"""Private subprocess trampoline: resource limits before replacing this process."""
import os
import ctypes
import signal
import resource
import sys

parent = int(os.environ.pop('TON_PARENT_PID', str(os.getppid())))
ctypes.CDLL(None).prctl(1, signal.SIGKILL)  # Linux PR_SET_PDEATHSIG
if os.getppid() != parent:
    os._exit(1)
seconds = int(sys.argv[1])
resource.setrlimit(resource.RLIMIT_CPU, (seconds, seconds + 1))
resource.setrlimit(resource.RLIMIT_AS, (768 * 1024**2, 768 * 1024**2))
resource.setrlimit(resource.RLIMIT_FSIZE, (4 * 1024**2, 4 * 1024**2))
resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
os.execv(sys.argv[2], sys.argv[2:])
