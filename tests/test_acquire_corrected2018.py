import hashlib
import io
import json
import re
import struct
import tempfile
import unittest
import zipfile
import zlib
from pathlib import Path

from attack_traffic.acquire_corrected2018 import MEMBER, URL, acquire_member


class Response(io.BytesIO):
    def __init__(self, data, status, headers):
        super().__init__(data)
        self.status, self.headers = status, headers


class AcquireTests(unittest.TestCase):
    def setUp(self):
        Path('.test-tmp').mkdir(exist_ok=True)

    def fixture(self, root, *, corruption=None):
        data = b'feature,label\n' + b'1,Benign\n' * 300000
        memory = io.BytesIO()
        with zipfile.ZipFile(memory, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
            with archive.open(MEMBER, 'w', force_zip64=True) as stream:
                stream.write(data)
            archive.writestr('Friday-16-02-2018.csv', b'NEVER READ LATER DATA')
        blob = memory.getvalue()
        if corruption in ('crc', 'size'):
            position = blob.index(b'PK\x01\x02') + (16 if corruption == 'crc' else 24)
            value = struct.unpack_from('<I', blob, position)[0]
            blob = blob[:position] + struct.pack('<I', value + 1) + blob[position + 4:]
        with zipfile.ZipFile(io.BytesIO(blob)) as archive:
            info = archive.getinfo(MEMBER)
            entries = [{'name': item.filename, 'compressed_bytes': item.compress_size,
                'uncompressed_bytes': item.file_size, 'crc32_claimed': f'{item.CRC:08x}'} for item in archive.infolist()]
            name_length, extra_length = struct.unpack_from('<HH', blob, info.header_offset + 26)
            payload_start = info.header_offset + 30 + name_length + extra_length
        inventory = {'source_url': URL, 'archive_bytes': len(blob),
            'http_headers': {'ETag': '"pinned"', 'Last-Modified': 'known'}, 'members': entries}
        inventory_path = root / 'inventory.json'
        inventory_path.write_text(json.dumps(inventory))
        requested = []

        def opener(request, timeout):
            headers = {'ETag': '"pinned"', 'Last-Modified': 'known', 'Content-Length': str(len(blob))}
            if request.get_method() == 'HEAD':
                return Response(b'', 200, headers)
            self.assertEqual(request.get_header('If-match'), '"pinned"')
            self.assertEqual(request.get_header('Accept-encoding'), 'identity')
            start, end = map(int, re.fullmatch(r'bytes=(\d+)-(\d+)', request.get_header('Range')).groups())
            requested.append((start, end))
            content = blob[start:end + 1]
            if corruption == 'short' and start == payload_start:
                content = content[:-1]
            headers.update({'Content-Length': str(end - start + 1), 'Content-Range': f'bytes {start}-{end}/{len(blob)}'})
            if corruption == 'range':
                headers['Content-Range'] = 'bytes 1-2/3'
            return Response(content, 206, headers)
        return inventory_path, opener, data, requested

    def test_streaming_verified_atomic_member_only(self):
        with tempfile.TemporaryDirectory(dir='.test-tmp') as tmp:
            root = Path(tmp)
            inventory, opener, data, ranges = self.fixture(root)
            output = root / 'output'
            acquire_member(inventory, output, opener=opener)
            self.assertEqual((output / MEMBER).read_bytes(), data)
            manifest = json.loads((output / 'acquisition.json').read_text())
            self.assertEqual(manifest['sha256'], hashlib.sha256(data).hexdigest())
            self.assertIsNone(manifest['archive_sha256'])
            self.assertEqual(manifest['bytes'], len(data))
            self.assertEqual(set(p.name for p in output.iterdir()), {MEMBER, 'acquisition.json'})
            self.assertIn(tuple(manifest['compressed_byte_range']), ranges)
            with self.assertRaises(ValueError):
                acquire_member(inventory, output, opener=opener)

    def test_bad_ranges_and_payloads_fail_without_publish(self):
        with tempfile.TemporaryDirectory(dir='.test-tmp') as tmp:
            root = Path(tmp)
            for corruption in ('range', 'short', 'crc', 'size'):
                inventory, opener, _, _ = self.fixture(root, corruption=corruption)
                output = root / corruption
                with self.assertRaises((ValueError, zlib.error)):
                    acquire_member(inventory, output, opener=opener)
                self.assertFalse(output.exists())
                self.assertFalse(list(root.glob('.corrected2018-member-*')))


if __name__ == '__main__':
    unittest.main()
