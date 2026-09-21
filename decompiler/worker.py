"""Per-request resource boundary, applied before importing compiler tooling."""
import json
import os
import resource
import sys

from .api import MAX_BODY, validate_request
from .errors import DecompilerError


def main():
    os.environ['TON_WORKER'] = '1'
    resource.setrlimit(resource.RLIMIT_AS, (1024 ** 3, 1024 ** 3))
    resource.setrlimit(resource.RLIMIT_CPU, (35, 35))
    resource.setrlimit(resource.RLIMIT_FSIZE, (32 * 1024 ** 2, 32 * 1024 ** 2))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    try:
        request = json.loads(sys.stdin.buffer.read(MAX_BODY + 1))
        boc, milliseconds = validate_request(request)
        from .service import decompile
        response = decompile(boc, max_search_time_ms=milliseconds)
        status = 200 if response['success'] else 422
    except DecompilerError as exc:
        status, response = exc.status, exc.response()
    except Exception:
        status = 500
        response = DecompilerError('INTERNAL_ERROR', 'Internal worker error', 'worker', 500).response()
    print(json.dumps({'status': status, 'response': response}, allow_nan=False))


if __name__ == '__main__':
    main()
