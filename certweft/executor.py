"""Root executor entry point; inherited lease fences takeover after parent death."""
import json,os,sys,signal,tempfile,stat
from pathlib import Path
from .core import Writer,Rejected,run

class FixedWriter(Writer):
    def reload(self):
        # Validation subprocess cannot publish or signal a delayed reload.
        run([self.nginx,'-t','-c',self.conf])
        pid=self.master['pid'];handle=os.pidfd_open(pid)
        try:
            raw=Path('/proc',str(pid),'stat').read_text()
            start=raw[raw.rfind(')')+2:].split()[19]
            if start!=self.master['start']:raise Rejected('master_identity')
            if os.path.realpath('/proc/'+str(pid)+'/exe')!=os.path.realpath(self.nginx):raise Rejected('master_binary')
            signal.pidfd_send_signal(handle,signal.SIGHUP)
        finally:os.close(handle)

def dispatch(config,request,peer_uid,checkpoint=lambda _:None):
    op=request.get('op')
    fields={'status':{'op'},'recover':{'op'},'activate':{'op','certificate','epoch','revision'}}
    if op not in fields or set(request)!=fields[op]:raise Rejected('request_shape')
    if op=='recover' and peer_uid!=0:raise Rejected('admin_required')
    if peer_uid not in {0,config['controller_uid']}:raise Rejected('peer_denied')
    root=Path(config['writer']['root']);st=root.lstat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid!=0 or st.st_mode & 0o077:raise Rejected('store_permissions')
    for field in ['key','conf','ca']:
        st=Path(config['writer'][field]).lstat()
        if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_mode & 0o022:raise Rejected('target_permissions')
    w=FixedWriter(**config['writer']);w.master=config['master']
    if op=='status':return w.status()
    if op=='recover':return w.recover()
    if type(request['certificate']) is not str or len(request['certificate'].encode())>32768:raise Rejected('certificate_budget')
    if type(request['epoch']) is not str or type(request['revision']) is not int:raise Rejected('authority_shape')
    # Copy bytes, never accept a caller-controlled file path or key/config.
    fd,path=tempfile.mkstemp(prefix='candidate-',dir=w.root)
    try:
        with os.fdopen(fd,'w') as f:f.write(request['certificate']);f.flush();os.fsync(f.fileno())
        return w.activate(path,request['epoch'],request['revision'],checkpoint)
    finally:Path(path).unlink(missing_ok=True)

def main():
    if os.geteuid()!=0:raise PermissionError('root executor required')
    lease=int(sys.argv[1]);request=json.load(sys.stdin);config=request['config']
    # Parent keeps the same open-file-description. No LOCK_UN anywhere.
    actual=os.fstat(lease);expected=os.stat(config['lease'])
    if (actual.st_dev,actual.st_ino)!=(expected.st_dev,expected.st_ino):raise Rejected('lease_identity')
    def checkpoint(point):
        # Root-owned VM fixture configuration only, never part of request API.
        if config.get('pause_at')==point:
            descendants=[]
            if config.get('pipe_holder'):
                import subprocess
                descendants.append(subprocess.Popen([sys.executable,'-c','import time;time.sleep(120)']).pid)
            marker=Path(config['marker']);pending=marker.with_suffix('.pending')
            pending.write_text(json.dumps({'pid':os.getpid(),'point':point,'descendants':descendants}))
            os.replace(pending,marker)
            os.kill(os.getpid(),signal.SIGSTOP)
    try:result={'ok':True,'result':dispatch(config,request['body'],request['peer_uid'],checkpoint)}
    except Exception as e:
        result={'ok':False,'error':type(e).__name__}
        if isinstance(e,Rejected):result['reason']=str(e)
    print(json.dumps(result))
if __name__=='__main__':main()
