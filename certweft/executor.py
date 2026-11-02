"""Root executor entry point; inherited lease fences takeover after parent death."""
import json,os,sys,signal,tempfile,stat
from contextlib import contextmanager
from pathlib import Path
from .core import Writer,Rejected,run
from .operations import Operations,Cancelled,StorageBlocked
from . import deadlines,storage
from .gate import Gate

class FixedWriter(Writer):
    operation_id=None
    sqlite_max_pages=None
    gate_authority=None
    @contextmanager
    def locked(self):
        with super().locked() as (db,lock):
            if self.sqlite_max_pages is not None:
                actual=db.execute('PRAGMA max_page_count='+str(self.sqlite_max_pages)).fetchone()[0]
                if actual!=self.sqlite_max_pages:raise Rejected('sqlite_quota_below_size')
            yield db,lock
    def save(self,db,state):
        if state.get('state')!='DEGRADED':deadlines.check()
        super().save(db,state)
    def recover_locked(self,db):
        if not self.operation_id:return super().recover_locked(db)
        try:
            record=Operations(self.root,self.sqlite_max_pages).recovery_budget(self.operation_id)
            with deadlines.use(record):
                getattr(self,'recovery_checkpoint',lambda _:None)('recovery')
                deadlines.check();return super().recover_locked(db)
        except deadlines.Expired:
            db.rollback();state=self.read(db);state['state']='DEGRADED'
            super().save(db,state)
            raise
    def commit_state(self,db,state):
        if self.operation_id:Operations.commit(db,self.operation_id,state,lambda:getattr(self,'commit_checkpoint',lambda _:None)('commit-decision'),self.gate_authority)
        else:super().commit_state(db,state)
    def reload(self):
        # Validation subprocess cannot publish or signal a delayed reload.
        run([self.nginx,'-t','-c',self.conf])
        pid=self.master['pid'];handle=os.pidfd_open(pid)
        try:
            raw=Path('/proc',str(pid),'stat').read_text()
            start=raw[raw.rfind(')')+2:].split()[19]
            if start!=self.master['start']:raise Rejected('master_identity')
            if self.master.get('binding')=='systemd':
                from .deployment import verify_unit_master
                verify_unit_master(self.master,self.nginx)
            elif os.path.realpath('/proc/'+str(pid)+'/exe')!=os.path.realpath(self.nginx):raise Rejected('master_binary')
            deadlines.check();signal.pidfd_send_signal(handle,signal.SIGHUP)
        finally:os.close(handle)

def dispatch(config,request,peer_uid,checkpoint=lambda _:None):
    op=request.get('op')
    fields={'status':{'op'},'recover':{'op'},'activate':{'op','certificate','epoch','revision'},'execute':{'op','request_id','certificate','epoch','revision'}}
    fields['recover-request']={'op','request_id'}
    if op not in fields or set(request)-({'timeout_seconds'} if op=='execute' else set())!=fields[op]:raise Rejected('request_shape')
    if op in {'recover','recover-request','execute'} and peer_uid!=0:raise Rejected('admin_required')
    if peer_uid not in {0,config['controller_uid']}:raise Rejected('peer_denied')
    root=Path(config['writer']['root']);st=root.lstat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid!=0 or st.st_mode & 0o077:raise Rejected('store_permissions')
    for field in ['key','conf','ca']:
        st=Path(config['writer'][field]).lstat()
        if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_mode & 0o022:raise Rejected('target_permissions')
    w=FixedWriter(**config['writer']);w.master=config['master'];w.recovery_checkpoint=checkpoint;w.commit_checkpoint=checkpoint;w.sqlite_max_pages=config.get('sqlite_max_pages')
    if op=='status':return w.status()
    if op=='recover':raise Rejected('use_prepare_recovery')
    if op=='recover-request':raise Rejected('use_prepare_recovery')
    from .opening import require_updates
    require_updates(root,config['gate_authority']);w.gate_authority=config['gate_authority']
    if type(request['certificate']) is not str or len(request['certificate'].encode())>32768:raise Rejected('certificate_budget')
    if type(request['epoch']) is not str or type(request['revision']) is not int:raise Rejected('authority_shape')
    operations=Operations(root,config.get('sqlite_max_pages'))
    if op=='execute':
        w.operation_id=request['request_id']
        if not operations.begin(w.operation_id):return operations.get(w.operation_id)
    # Copy bytes, never accept a caller-controlled file path or key/config.
    fd,path=tempfile.mkstemp(prefix='candidate-',dir=w.root)
    try:
        with os.fdopen(fd,'w') as f:f.write(request['certificate']);f.flush();os.fsync(f.fileno())
        owned_intent=[False]
        def boundary(point):
            if point=='intent':owned_intent[0]=True
            checkpoint(point)
            if w.operation_id:
                deadlines.check();operations.check_cancel(w.operation_id)
        try:
            if w.operation_id:
                with deadlines.use(operations.get(w.operation_id)['timing']['activation']):
                    checkpoint('preparing');deadlines.check()
                    result=w.activate(path,request['epoch'],request['revision'],boundary)
            else:result=w.activate(path,request['epoch'],request['revision'],boundary)
            return operations.get(w.operation_id) if w.operation_id else result
        except Exception as error:
            if not w.operation_id:raise
            # An exception before core's try block may leave durable APPLYING.
            try:
                state=w.status()
                if state['state']=='APPLYING' and owned_intent[0]:
                    w.recover();state=w.status()
                if storage.failed(error):operations.latch_storage(error)
                if state['state']!='READY' or storage.failed(error) or isinstance(error,StorageBlocked):terminal='DEGRADED'
                else:
                    if isinstance(error,Cancelled):terminal='ROLLED_BACK'
                    elif isinstance(error,deadlines.Expired):terminal='ROLLED_BACK' if owned_intent[0] else 'EXPIRED'
                    else:terminal='FAILED'
            except Exception:terminal='DEGRADED'
            return operations.finish(w.operation_id,terminal,{'error':type(error).__name__,'expired':isinstance(error,deadlines.Expired),'sqlite_error':getattr(error,'sqlite_errorname',None),'errno':getattr(error,'errno',None)})
    finally:Path(path).unlink(missing_ok=True)

def main():
    if os.geteuid()!=0:raise PermissionError('root executor required')
    lease=int(sys.argv[1]);request=json.load(sys.stdin);config=request['config']
    # Parent keeps the same open-file-description. No LOCK_UN anywhere.
    actual=os.fstat(lease);expected=os.stat(config['lease'])
    if (actual.st_dev,actual.st_ino)!=(expected.st_dev,expected.st_ino):raise Rejected('lease_identity')
    def checkpoint(point):
        if config.get('delay_at')==point:
            import time;time.sleep(config['delay_seconds'])
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
        result={'ok':False,'error':type(e).__name__,'sqlite_error':getattr(e,'sqlite_errorname',None),'errno':getattr(e,'errno',None)}
        if isinstance(e,Rejected):result['reason']=str(e)
    print(json.dumps(result))
if __name__=='__main__':main()
