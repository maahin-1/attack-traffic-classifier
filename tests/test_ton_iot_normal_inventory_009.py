import json
import struct

from scripts import ton_iot_normal_inventory_009 as inventory


def test_inventory_counts_and_does_not_publish_endpoints(tmp_path, monkeypatch):
    capture=tmp_path/'normal_13.pcap'
    sll=bytearray(16); sll[14:16]=b'\x08\x00'
    ip=bytearray(20); ip[0]=0x45; ip[2:4]=(28).to_bytes(2,'big'); ip[9]=17
    ip[12:16]=bytes([192,0,2,1]); ip[16:20]=bytes([198,51,100,2])
    frame=bytes(sll+ip)+struct.pack('!HHHH',1234,53,8,0)
    header=bytes.fromhex('d4c3b2a1')+struct.pack('<HHIIII',2,4,0,0,65535,113)
    record=struct.pack('<IIII',1556021522,50,len(frame),len(frame))+frame
    capture.write_bytes(header+record)
    output=tmp_path/'output'
    monkeypatch.setattr(inventory,'PCAP',capture)
    monkeypatch.setattr(inventory,'OUT',output)
    inventory.main()
    report=json.loads((output/'report.json').read_text())
    assert report['transport']=={'udp':1}
    assert report['packet_stats']['packets']==1
    assert report['time_range_comparisons']['csv_events']['ranges_overlap'] is True
    assert report['benign_status']=='unverified'
    assert '192.0.2.1' not in (output/'report.json').read_text()
