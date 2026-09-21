import hashlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError

from scripts.bootstrap import download


class BootstrapTests(unittest.TestCase):
    def test_download_retries_gateway_timeout(self):
        data = b'pinned asset'
        error = HTTPError('https://example.test/asset', 504, 'timeout', {}, None)
        with tempfile.TemporaryDirectory() as directory, \
                patch('scripts.bootstrap.urllib.request.urlopen', side_effect=[error, io.BytesIO(data)]), \
                patch('scripts.bootstrap.time.sleep') as sleep:
            target = Path(directory) / 'asset'
            download('https://example.test/asset', target, hashlib.sha256(data).hexdigest())
            self.assertEqual(target.read_bytes(), data)
            sleep.assert_called_once_with(1)


if __name__ == '__main__':
    unittest.main()
