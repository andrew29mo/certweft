"""Formal-service repaired-storage restart gate and root CAS contract evidence."""
import html,json,os,pathlib,shutil,sys,time,traceback
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
from tools.storage_vm import scenario
from tools.executor_vm import hashes
P=pathlib.Path(__file__).resolve().parents[1]
def main():
    if os.geteuid()!=0:raise PermissionError('isolated VM root required')
    os.umask(0o077);source=hashes();out=P/'evidence/restart-gate.json'
    if out.exists():
        archive=P/'evidence/gate-attempts';archive.mkdir(exist_ok=True);shutil.copyfile(out,archive/(str(time.time_ns())+'.json'))
    def publish(r):
        text=json.dumps(r,indent=2);out.write_text(text);out.with_suffix('.html').write_text('<!doctype html><meta charset="utf-8"><pre>'+html.escape(text)+'</pre>')
    report={'passed':False,'status':'in_progress','cases':[],'scope':'source-run root certweft.service/executor; real Nginx; repaired private ext4 loop store in isolated Linux VM','untested':['full safe recovery/unlock backend','persistent systemd deployment','VM reboot','power loss','physical media loss','D-state executor','trusted root tampering']};publish(report)
    try:
        for kind,phase in [('enospc','pre'),('enospc','post'),('readonly','pre'),('readonly','post'),('sqlite_full','cancel_unrecorded')]:
            try:detail=scenario(kind,phase,check_gate=True)
            except Exception as error:
                report['cases'].append({'fault':kind,'phase':phase,'passed':False,'error':type(error).__name__+': '+str(error)});raise
            report['cases'].append(detail);publish(report)
        report['passed']=True;report['status']='completed'
    except Exception as error:
        traceback.print_exc();report['error']=type(error).__name__+': '+str(error);report['status']='failed'
    report['source_sha256']=source;report['source_unchanged']=source==hashes();report['passed']=report['passed'] and report['source_unchanged'];report['environment']={'python':sys.version.split()[0],'kernel':os.uname().release,'machine':os.uname().machine};publish(report)
    print(json.dumps({'passed':report['passed'],'cases':len(report['cases']),'error':report.get('error')}));return 0 if report['passed'] else 1
if __name__=='__main__':sys.exit(main())
