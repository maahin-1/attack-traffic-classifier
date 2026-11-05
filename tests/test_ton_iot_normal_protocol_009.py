import struct
from scripts.ton_iot_normal_protocol_009 import classify


def test_linux_cooked_ipv6_and_ipv4_protocols():
    sll=bytearray(16);sll[14:16]=b'\x86\xdd'
    assert classify(bytes(sll)+bytes(40),113)==('ethertype_0x86dd',None,False)
    sll[14:16]=b'\x08\x00';ip=bytearray(20);ip[0]=0x45;ip[9]=1
    assert classify(bytes(sll+ip),113)==('ipv4',1,False)
    ip[6:8]=struct.pack('!H',1)
    assert classify(bytes(sll+ip),113)==('ipv4',1,True)


def test_truncated_link_header_is_not_assigned_to_a_protocol():
    assert classify(bytes(12),113)==('truncated_link',None,False)
