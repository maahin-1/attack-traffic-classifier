import struct
from scripts.ton_iot_normal_sll_009 import candidate_offsets


def test_finds_checksummed_header_at_nonzero_offset():
    header=bytearray(20);header[0]=0x45;header[2:4]=(28).to_bytes(2,'big');header[9]=17
    words=struct.unpack('!10H',header);value=sum(words);value=(value&65535)+(value>>16);value=(value&65535)+(value>>16)
    header[10:12]=((~value)&65535).to_bytes(2,'big')
    assert candidate_offsets(b'\0\0'+bytes(header)+b'\0'*8)==[2]
    header[10]^=1
    assert candidate_offsets(b'\0\0'+bytes(header)+b'\0'*8)==[]


def test_short_buffer_has_no_candidates():
    assert candidate_offsets(b'\x45\0')==[]
