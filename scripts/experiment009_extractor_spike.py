"""Generate synthetic PCAP fixtures and run a pinned offline extractor candidate."""
import csv
import hashlib
import json
import os
import struct
import subprocess
import sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'artifacts/experiment-009-extractor-spike'
PLAN=ROOT/'docs/EXPERIMENT-009-EXTRACTOR-SPIKE-PLAN.md'
WHEEL=ROOT/'.test-tmp/extractor-wheels-009/cicflowmeter-0.4.0-py3-none-any.whl'
EXPECTED_WHEEL='5bcef1ef131a53a037a47b007b33b5e73d4218033fdf6cb9f3208533180c30be'


def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def checksum(data):
    if len(data)%2:data+=b'\0'
    total=sum(struct.unpack('!'+str(len(data)//2)+'H',data))
    while total>>16:total=(total&65535)+(total>>16)
    return (~total)&65535


def tcp_packet(reverse=False):
    a=bytes([192,0,2,1]);b=bytes([198,51,100,2])
    source,destination=(b,a) if reverse else (a,b)
    sp,dp=(443,12345) if reverse else (12345,443)
    tcp=struct.pack('!HHIIHHHH',sp,dp,1,0,(5<<12)|0x10,8192,0,0)
    pseudo=source+destination+struct.pack('!BBH',0,6,len(tcp))
    tcp=tcp[:16]+struct.pack('!H',checksum(pseudo+tcp))+tcp[18:]
    ip=struct.pack('!BBHHHBBH4s4s',0x45,0,40,0,0,64,6,0,source,destination)
    ip=ip[:10]+struct.pack('!H',checksum(ip))+ip[12:]
    return ip+tcp


def fixture(linktype):
    header=bytes.fromhex('d4c3b2a1')+struct.pack('<HHIIII',2,4,0,0,65535,linktype)
    output=bytearray(header)
    for sec,micro,reverse in ((1700000000,100000,False),(1700000000,600000,True),(1700000001,100000,False)):
        ip=tcp_packet(reverse)
        if linktype==1:frame=bytes.fromhex('0200000000020200000000010800')+ip
        elif linktype==113:frame=struct.pack('!HHH8sH',0,1,6,bytes.fromhex('0200000000010000'),0x0800)+ip
        else:raise ValueError('unsupported fixture link')
        output.extend(struct.pack('<IIII',sec,micro,len(frame),len(frame)));output.extend(frame)
    return bytes(output)


def main():
    if sys.prefix==sys.base_prefix:raise ValueError('requires isolated test environment')
    if sha(WHEEL)!=EXPECTED_WHEEL:raise ValueError('wheel hash mismatch')
    if OUT.exists():raise FileExistsError(OUT)
    OUT.mkdir(parents=True)
    environment=dict(os.environ,PYTHONNOUSERSITE='1')
    version=subprocess.run([sys.executable,'-m','pip','freeze'],capture_output=True,text=True,check=True,env=environment).stdout.splitlines()
    protocol={'fixture':'3 TCP packets: 2 forward, 1 backward; first to last duration 1 second',
              'extractor':'Python cicflowmeter 0.4.0, not UNB Java','wheel_sha256':EXPECTED_WHEEL,
              'python':sys.version,'dependencies':version,'runner_sha256':sha(Path(__file__)),'plan_sha256':sha(PLAN)}
    (OUT/'protocol.json').write_text(json.dumps(protocol,indent=2)+'\n',encoding='utf-8')
    executable=Path(sys.executable).parent/'cicflowmeter.exe';results={}
    for kind,linktype in (('ethernet',1),('linux_cooked_v1',113)):
        path=OUT/(kind+'.pcap');path.write_bytes(fixture(linktype));output=OUT/(kind+'.csv')
        args=[str(executable),'-f',str(path),'-c',str(output)]
        try:
            done=subprocess.run(args,capture_output=True,text=True,timeout=60,env=environment,cwd=ROOT)
            result={'exit_code':done.returncode,'stdout':done.stdout,'stderr':done.stderr,'fixture_sha256':sha(path),'output_exists':output.is_file()}
        except subprocess.TimeoutExpired as exc:
            result={'exit_code':None,'timeout_seconds':60,'fixture_sha256':sha(path),'output_exists':output.is_file(),'error':str(exc)}
        if output.is_file():
            with output.open(encoding='utf-8-sig',newline='') as stream:
                reader=csv.DictReader(stream); rows=list(reader)
                result.update({'columns':reader.fieldnames,'row_count':len(rows),'rows':rows})
        results[kind]=result
        (OUT/'progress.json').write_text(json.dumps({'finished':list(results)})+'\n',encoding='utf-8')
    if sha(WHEEL)!=EXPECTED_WHEEL or sha(Path(__file__))!=protocol['runner_sha256'] or sha(PLAN)!=protocol['plan_sha256']:raise ValueError('source changed during spike')
    (OUT/'report.json').write_text(json.dumps({'status':'complete','cases':results,'protocol_sha256':sha(OUT/'protocol.json')},indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:{'exit_code':v['exit_code'],'row_count':v.get('row_count'),'error':v.get('error')} for k,v in results.items()}))


if __name__=='__main__':main()
