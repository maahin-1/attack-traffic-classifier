"""Acquire only the designated corrected-2018 development ZIP member.

The archive is not downloaded or hashed in full. Load only a trusted inventory;
its size, ETag and member metadata are checked against the live ZIP directory.
"""
import hashlib
import io
import json
import shutil
import struct
import tempfile
import urllib.request
import zipfile
import zlib
from datetime import datetime, timezone
from pathlib import Path

URL = 'https://intrusion-detection.distrinet-research.be/CNS2022/Datasets/CSECICIDS2018_improved.zip'
MEMBER = 'Wednesday-14-02-2018.csv'


class RemoteDirectory(io.RawIOBase):
    def __init__(self, inventory, opener):
        self.opener = opener
        self.size = inventory['archive_bytes']
        self.etag = inventory['http_headers']['ETag']
        self.last_modified = inventory['http_headers']['Last-Modified']
        self.position = 0
        self.ranges = []
        self.transferred = 0
        with opener(urllib.request.Request(URL, method='HEAD', headers={'Accept-Encoding': 'identity'}), timeout=60) as response:
            if (response.status != 200 or int(response.headers.get('Content-Length', -1)) != self.size
                    or response.headers.get('ETag') != self.etag
                    or response.headers.get('Last-Modified') != self.last_modified):
                raise ValueError('Archive identity differs from pinned inventory')

    def tell(self):
        return self.position

    def seekable(self):
        return True

    def seek(self, offset, whence=0):
        self.position = offset if whence == 0 else self.position + offset if whence == 1 else self.size + offset
        if not 0 <= self.position <= self.size:
            raise ValueError('Invalid ZIP seek')
        return self.position

    def response(self, start, length):
        if length <= 0 or start < 0 or start + length > self.size:
            raise ValueError('Invalid range')
        request = urllib.request.Request(URL, headers={'Range': f'bytes={start}-{start + length - 1}',
            'If-Match': self.etag, 'Accept-Encoding': 'identity'})
        response = self.opener(request, timeout=60)
        if (response.status != 206 or response.headers.get('Content-Range') != f'bytes {start}-{start + length - 1}/{self.size}'
                or int(response.headers.get('Content-Length', -1)) != length
                or response.headers.get('ETag') != self.etag
                or response.headers.get('Content-Encoding', 'identity') != 'identity'):
            response.close()
            raise ValueError('Range/identity response mismatch')
        return response

    def read(self, length=-1):
        length = self.size - self.position if length < 0 else min(length, self.size - self.position)
        if not length:
            return b''
        if length > 262144 or self.transferred + length > 2097152:
            raise ValueError('ZIP metadata transfer cap exceeded')
        start = self.position
        with self.response(start, length) as response:
            data = response.read(length + 1)
        if len(data) != length:
            raise ValueError('Incomplete metadata range')
        self.position += length
        self.transferred += length
        self.ranges.append([start, start + length - 1])
        return data


def acquire_member(inventory_path, output_dir, *, opener=urllib.request.urlopen):
    """Publish verified CSV and acquisition.json atomically to a fresh directory."""
    inventory_path, output = Path(inventory_path), Path(output_dir).resolve()
    if output.exists():
        raise ValueError('Output already exists')
    raw_inventory = inventory_path.read_bytes()
    inventory = json.loads(raw_inventory)
    if inventory.get('source_url') != URL:
        raise ValueError('Unexpected archive URL')
    entries = [entry for entry in inventory['members'] if entry['name'] == MEMBER]
    if len(entries) != 1:
        raise ValueError('Development member missing or duplicated')
    expected = entries[0]
    remote = RemoteDirectory(inventory, opener)
    with zipfile.ZipFile(remote) as archive:
        if len(archive.namelist()) != len(set(archive.namelist())):
            raise ValueError('Duplicate ZIP names')
        member = archive.getinfo(MEMBER)
        if (member.compress_size != expected['compressed_bytes'] or member.file_size != expected['uncompressed_bytes']
                or f'{member.CRC:08x}' != expected['crc32_claimed'] or member.compress_type != zipfile.ZIP_DEFLATED
                or member.flag_bits & 1):
            raise ValueError('ZIP member differs from inventory or unsupported encoding')
        remote.seek(member.header_offset)
        header = remote.read(30)
        fields = struct.unpack('<4s5H3I2H', header)
        if fields[0] != b'PK\x03\x04' or fields[2] != member.flag_bits or fields[3] != member.compress_type:
            raise ValueError('Invalid ZIP local header')
        name_length, extra_length = fields[-2:]
        local_name = remote.read(name_length)
        if local_name.decode('utf-8' if member.flag_bits & 2048 else 'cp437') != MEMBER:
            raise ValueError('ZIP local filename differs')
        start = member.header_offset + 30 + name_length + extra_length
        end = start + member.compress_size
        next_offsets = [item.header_offset for item in archive.infolist() if item.header_offset > member.header_offset]
        if end > min(next_offsets + [archive.start_dir]):
            raise ValueError('Member overlaps ZIP metadata or another member')
    output.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix='.corrected2018-member-', dir=output.parent))
    try:
        sha, compressed_sha, crc, written = hashlib.sha256(), hashlib.sha256(), 0, 0
        decompressor = zlib.decompressobj(-15)
        with remote.response(start, member.compress_size) as response, (stage / MEMBER).open('xb') as stream:
            remaining = member.compress_size
            while remaining:
                block = response.read(min(1048576, remaining))
                if not block:
                    raise ValueError('Incomplete compressed member')
                remaining -= len(block)
                compressed_sha.update(block)
                pending = block
                while pending:
                    expanded = decompressor.decompress(pending, 1048576)
                    pending = decompressor.unconsumed_tail
                    written += len(expanded)
                    if written > member.file_size:
                        raise ValueError('Expanded member exceeds pinned size')
                    stream.write(expanded)
                    sha.update(expanded)
                    crc = zlib.crc32(expanded, crc)
            if response.read(1):
                raise ValueError('Range exceeded requested compressed bytes')
        if (not decompressor.eof or decompressor.unused_data or written != member.file_size
                or crc != member.CRC):
            raise ValueError('Member CRC, size or deflate stream verification failed')
        record = {'schema_version': 1, 'source_url': URL, 'archive_bytes': remote.size,
            'archive_etag': remote.etag, 'archive_last_modified': remote.last_modified,
            'archive_sha256': None, 'file': MEMBER, 'bytes': written, 'sha256': sha.hexdigest(),
            'compressed_member_bytes': member.compress_size, 'compressed_member_sha256': compressed_sha.hexdigest(),
            'member_crc32_verified': f'{crc:08x}', 'compressed_byte_range': [start, end - 1],
            'metadata_byte_ranges': remote.ranges, 'metadata_bytes_transferred': remote.transferred,
            'inventory_sha256': hashlib.sha256(raw_inventory).hexdigest(),
            'role': 'corrected 2018 development member only; no model scoring',
            'retrieved_at': datetime.now(timezone.utc).isoformat(),
            'limitations': 'Whole archive not acquired or hashed. Member CRC validates integrity, not historical producer provenance or capture completeness.'}
        (stage / 'acquisition.json').write_text(json.dumps(record, indent=2) + '\n', encoding='utf-8')
        stage.rename(output)
    except BaseException:
        shutil.rmtree(stage)
        raise
    return output
