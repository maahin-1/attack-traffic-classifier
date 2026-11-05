import io
import struct
from collections import Counter

import pytest

from scripts.ton_iot_scanning_probe_009 import decode, iter_packets
from scripts.ton_iot_scanning_starts_009 import first_header
from scripts.ton_iot_scanning1_probe_009 import packets


def block(kind, payload):
    payload += b'\0' * (-len(payload) % 4)
    length=12+len(payload)
    return struct.pack('<II',kind,length)+payload+struct.pack('<I',length)


def sample_frame():
    sll=bytearray(16); sll[14:16]=b'\x08\x00'
    ip=bytearray(20); ip[0]=0x45; ip[2:4]=(28).to_bytes(2,'big'); ip[9]=17
    ip[12:16]=bytes([192,0,2,1]); ip[16:20]=bytes([198,51,100,2])
    return bytes(sll+ip)+struct.pack('!HHHH',1234,53,8,0)


def test_linux_cooked_udp_and_timestamp_resolution():
    frame=sample_frame(); ticks=1556021522123456
    section=block(0x0a0d0d0a,struct.pack('<IHHq',0x1a2b3c4d,1,0,-1))
    interface=block(1,struct.pack('<HHI',113,0,65535))
    packet=block(6,struct.pack('<IIIII',0,ticks>>32,ticks&0xffffffff,len(frame),len(frame))+frame)
    stats=Counter(); result=list(iter_packets(io.BytesIO(section+interface+packet),stats))
    assert result[0][0]==1556021522
    assert result[0][1]==(17,bytes([192,0,2,1]),1234,bytes([198,51,100,2]),53)
    assert stats['packets']==1 and stats['interface_113_ticks_1000000_offset_0']==1


def test_invalid_block_trailer_fails():
    section=block(0x0a0d0d0a,struct.pack('<IHHq',0x1a2b3c4d,1,0,-1))
    broken=section[:-4]+struct.pack('<I',99)
    with pytest.raises(ValueError,match='trailer'):
        list(iter_packets(io.BytesIO(broken),Counter()))


def test_noninitial_ipv4_fragments_are_skipped():
    frame=bytearray(sample_frame()); frame[16+6:16+8]=b'\x00\x01'
    assert decode(bytes(frame),113) is None


def test_start_inventory_does_not_read_packet_payload():
    frame=sample_frame(); ticks=1556021522123456
    section=block(0x0a0d0d0a,struct.pack('<IHHq',0x1a2b3c4d,1,0,-1))
    interface=block(1,struct.pack('<HHI',113,0,65535))
    packet=block(6,struct.pack('<IIIII',0,ticks>>32,ticks&0xffffffff,len(frame),len(frame))+frame)
    stream=io.BytesIO(section+interface+packet)
    result=first_header(stream)
    assert result['first_packet_utc_interpretation']=='2019-04-23T12:12:02+00:00'
    assert result['link_type']==113
    assert stream.tell()==len(section)+len(interface)+28


def test_start_inventory_supports_classic_pcap_without_payload():
    header=bytes.fromhex('d4c3b2a1')+struct.pack('<HHIIII',2,4,0,0,65535,1)
    record=struct.pack('<IIII',1556021522,123,10,10)+b'0123456789'
    stream=io.BytesIO(header+record)
    assert first_header(stream)['first_packet_utc_interpretation']=='2019-04-23T12:12:02+00:00'
    assert stream.tell()==40


def test_classic_capture_packet_match_decoder():
    frame=sample_frame()
    header=bytes.fromhex('d4c3b2a1')+struct.pack('<HHIIII',2,4,0,0,65535,113)
    record=struct.pack('<IIII',1556021522,123,len(frame),len(frame))+frame
    stats=Counter(); result=list(packets(io.BytesIO(header+record),stats))
    assert result[0][0]==1556021522
    assert result[0][1]==(17,bytes([192,0,2,1]),1234,bytes([198,51,100,2]),53)
    assert stats['packets']==1
