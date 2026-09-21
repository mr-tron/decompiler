"""Bounded HTTP ingress. Each request runs in an isolated, disposable process."""
import base64
import binascii
import json
import logging
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .boc import MAX_BYTES, BocError, parse_boc
from .errors import DecompilerError

MAX_BODY = (MAX_BYTES + 2) // 3 * 4 + 1024
MAX_SEARCH_MS = 30_000


def validate_request(value):
    if not isinstance(value, dict) or set(value) - {'code', 'max_search_time_ms'}:
        raise DecompilerError('INVALID_REQUEST', 'Expected code and optional max_search_time_ms', 'input', 400)
    code = value.get('code')
    if not isinstance(code, str) or len(code) > (MAX_BYTES + 2) // 3 * 4:
        raise DecompilerError('INVALID_BASE64', 'code must be a base64 string of at most 1 MiB decoded', 'input', 400)
    milliseconds = value.get('max_search_time_ms', 30_000)
    if type(milliseconds) is not int or not 1 <= milliseconds <= MAX_SEARCH_MS:
        raise DecompilerError('INVALID_REQUEST', 'max_search_time_ms must be an integer from 1 to 30000', 'input', 400)
    try:
        boc = base64.b64decode(code, validate=True)
    except (ValueError, binascii.Error):
        raise DecompilerError('INVALID_BASE64', 'code is not valid base64', 'input', 400) from None
    try:
        parse_boc(boc)
    except BocError as exc:
        raise DecompilerError('INVALID_BOC', str(exc), 'boc', 400) from None
    return boc, milliseconds


def run_worker(request):
    _, milliseconds = validate_request(request)
    with tempfile.TemporaryDirectory(prefix='ton-worker-') as temporary:
        with subprocess.Popen([sys.executable, '-m', 'decompiler.worker'],
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              cwd=Path(__file__).resolve().parent.parent,
                              start_new_session=True, env={**os.environ, 'TMPDIR': temporary}) as process:
            try:
                stdout, _ = process.communicate(json.dumps(request).encode(), timeout=milliseconds / 1000 + 5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.communicate()
                raise DecompilerError('RESOURCE_LIMIT', 'Request exceeded its execution deadline', 'search', 504) from None
            finally:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            if process.returncode or len(stdout) > 8 * MAX_BYTES:
                raise DecompilerError('WORKER_FAILED', 'Worker failed or exceeded resource limits', 'worker', 500)
    try:
        envelope = json.loads(stdout)
        return envelope['status'], envelope['response']
    except (ValueError, KeyError, TypeError):
        raise DecompilerError('WORKER_FAILED', 'Invalid worker response', 'worker', 500) from None


class Server(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 16
    allow_reuse_address = True

    def __init__(self, address, handler=None):
        super().__init__(address, handler or Handler)
        self.slots = threading.BoundedSemaphore(4)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            try:
                request.settimeout(1)
                body = b'{"success":false,"error":{"code":"BUSY","message":"All workers are busy","stage":"worker"},"diagnostics":[]}'
                request.sendall(b'HTTP/1.0 503 Service Unavailable\r\nContent-Type: application/json\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n\r\n' + body)
            except OSError:
                pass
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()


class Handler(BaseHTTPRequestHandler):
    server_version = 'TVMDecompiler/0.1'

    def setup(self):
        super().setup()
        self.connection.settimeout(10)

    def respond(self, status, result):
        body = json.dumps(result, ensure_ascii=True, allow_nan=False).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        try:
            if self.path != '/v1/decompile':
                raise DecompilerError('NOT_FOUND', 'Unknown endpoint', 'http', 404)
            if self.headers.get_content_type() != 'application/json':
                raise DecompilerError('INVALID_REQUEST', 'Content-Type must be application/json', 'http', 415)
            lengths = self.headers.get_all('Content-Length', [])
            if len(lengths) != 1 or not lengths[0].isascii() or not lengths[0].isdigit() or self.headers.get('Transfer-Encoding'):
                raise DecompilerError('INVALID_REQUEST', 'A single Content-Length is required', 'http', 400)
            length = int(lengths[0])
            if not 0 < length <= MAX_BODY:
                raise DecompilerError('INPUT_TOO_LARGE', 'Request body exceeds size limit', 'http', 413)
            try:
                payload = self.rfile.read(length)
                if len(payload) != length:
                    raise ValueError('Incomplete body')
                request = json.loads(payload)
            except (ValueError, UnicodeError, RecursionError):
                raise DecompilerError('INVALID_JSON', 'Expected a valid JSON object', 'http', 400) from None
            self.respond(*run_worker(request))
        except DecompilerError as exc:
            self.respond(exc.status, exc.response())
        except (TimeoutError, ConnectionError):
            self.close_connection = True
        except Exception:
            logging.exception('Request failed')
            exc = DecompilerError('INTERNAL_ERROR', 'Internal server error', 'internal', 500)
            self.respond(exc.status, exc.response())

    def do_GET(self):
        if self.path == '/':
            body = Path(__file__).with_name('index.html').read_bytes()
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Content-Security-Policy', "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
            self.end_headers()
            self.wfile.write(body)
            return
        exc = DecompilerError('NOT_FOUND', 'Use POST /v1/decompile', 'http', 404)
        self.respond(exc.status, exc.response())


def serve(host='127.0.0.1', port=8080):
    with Server((host, port)) as server:
        logging.warning('Listening on http://%s:%s', host, port)
        server.serve_forever()
