import io
import struct

from scripts.packet_multi_inventory_008 import HashedReader, scan


def test_inventory_counts_flags_and_packet_bytes():
    ip=bytearray(20); ip[0]=0x45; ip[2:4]=(40).to_bytes(2,'big'); ip[9]=6
    tcp=bytearray(20); tcp[12]=0x50; tcp[13]=0x42
    frame=b'\0'*12+b'\x08\x00'+bytes(ip+tcp)
    header=bytes.fromhex('d4c3b2a1')+struct.pack('<HHiIII',2,4,0,0,65535,1)
    record=struct.pack('<IIII',1700000000,1,len(frame),len(frame))+frame
    reader=HashedReader(io.BytesIO(header+record))
    result=scan(reader)
    assert result['packets']==1 and result['parseable_ipv4_tcp_packets']==1
    assert result['flag_packet_counts']['SYN']==1 and result['flag_packet_counts']['ECE']==1
    assert result['flag_packet_counts']['URG']==0 and reader.bytes==len(header+record)


def test_truncated_final_packet_is_reported_and_not_counted():
    header=bytes.fromhex('d4c3b2a1')+struct.pack('<HHiIII',2,4,0,0,65535,1)
    record=struct.pack('<IIII',1700000000,1,40,40)+b'123'
    result=scan(HashedReader(io.BytesIO(header+record)))
    assert result['packets']==0
    assert result['truncated_final_record']=={'kind':'packet_data','bytes_available':3,'bytes_expected':40}
