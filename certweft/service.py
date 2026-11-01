"""Fixed local privileged writer. One bounded request/executor at a time."""
import fcntl,json,os,socket,stat,struct,subprocess,sys,threading
from .operations import Operations
from .core import Rejected,Writer
from pathlib import Path

def secure_parents(path):
    for parent in Path(path).absolute().parents:
        st=parent.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid!=0:raise PermissionError('untrusted parent')
        if st.st_mode & 0o022 and not (st.st_mode & stat.S_ISVTX):raise PermissionError('writable parent')

def load_config(path):
    secure_parents(path)
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(fd) as stream:
        st=os.fstat(stream.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_mode & 0o022:raise PermissionError('untrusted configuration')
        config=json.load(stream)
    for target in [config['lease'],config['socket'],*map(config['writer'].get,['root','key','conf','ca','nginx'])]:secure_parents(target)
    binary=Path(config['writer']['nginx']).lstat()
    if not stat.S_ISREG(binary.st_mode) or binary.st_uid!=0 or binary.st_mode & 0o022:raise PermissionError('untrusted binary')
    return config

def start_work(operations,body,target,fail_start=False):
    try:
        if fail_start:raise RuntimeError('injected_dispatch_failure')
        threading.Thread(target=target,args=(body,),daemon=True).start()
    except Exception:
        try:operations.finish(body['request_id'],'FAILED',{'error':'dispatch_failed','executed':False})
        except Exception:os._exit(75)
        raise

def serve(config_path):
    if os.geteuid()!=0:raise PermissionError('root writer required')
    config=load_config(config_path);lease_path=Path(config['lease'])
    fd=os.open(lease_path,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    try:
        st=os.fstat(fd)
        if st.st_uid!=0 or st.st_mode & 0o077:raise PermissionError('lease_permissions')
        try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:
            print('lease_busy',flush=True);raise SystemExit(73)
        root=Path(config['writer']['root']);store=root.lstat()
        if not stat.S_ISDIR(store.st_mode) or store.st_uid!=0 or store.st_mode & 0o077:raise PermissionError('store_permissions')
        journal=(root/'journal.db').lstat()
        if not stat.S_ISREG(journal.st_mode) or journal.st_uid!=0 or journal.st_mode & 0o077:raise PermissionError('journal_permissions')
        operations=Operations(root);operations.initialize()
        guard=threading.Lock()
        def execute(body,uid):
            child=subprocess.Popen([sys.executable,'-m','certweft.executor',str(fd)],
                start_new_session=True,pass_fds=(fd,),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            if config.get('executor_inventory'):
                raw=Path('/proc',str(child.pid),'stat').read_text()
                record=json.dumps({'pid':child.pid,'start':raw[raw.rfind(')')+2:].split()[19]})+'\n'
                inventory=os.open(config['executor_inventory'],os.O_WRONLY|os.O_CREAT|os.O_APPEND|os.O_NOFOLLOW,0o600)
                try:os.write(inventory,record.encode())
                finally:os.close(inventory)
            try:out,err=child.communicate(json.dumps({'body':body,'peer_uid':uid,'config':config}).encode(),timeout=20)
            except subprocess.TimeoutExpired:
                import signal
                os.killpg(child.pid,signal.SIGKILL)
                try:child.communicate(timeout=3)
                except subprocess.TimeoutExpired:os._exit(75)
                raise TimeoutError('executor_timeout')
            if child.returncode!=0 or len(out)>16384:raise RuntimeError('executor_failure')
            return json.loads(out)
        # Lease excludes old executors before reconciling unfinished requests.
        pending=operations.pending()
        if pending:
            state=Writer(**config['writer']).status()
            if state['state']=='DEGRADED':
                for identity in pending:operations.finish(identity,'DEGRADED',{'recovered':False,'replayed':False,'error':'startup_degraded'})
            else:
                recovered=execute({'op':'recover'},0)
                if not recovered['ok']:raise RuntimeError('startup_recovery_failed')
                for identity in pending:operations.finish(identity,'INTERRUPTED',{'recovered':True,'replayed':False})
        def work(body):
            try:
                reply=execute({'op':'execute',**{k:v for k,v in body.items() if k!='op'}},0)
                if not reply.get('ok'):operations.finish(body['request_id'],'DEGRADED',{'executor_error':reply.get('error')})
            except Exception as error:
                try:operations.finish(body['request_id'],'DEGRADED',{'executor_error':type(error).__name__})
                except Exception:os._exit(75)
            finally:guard.release()
        endpoint=Path(config['socket'])
        if endpoint.exists():endpoint.unlink()
        with socket.socket(socket.AF_UNIX) as server:
            server.bind(str(endpoint));os.chown(endpoint,config['controller_uid'],-1);os.chmod(endpoint,0o600)
            server.listen(4)
            while True:
                conn,_=server.accept()
                with conn:
                    conn.settimeout(2)
                    _,uid,_=struct.unpack('3i',conn.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
                    if uid not in {0,config['controller_uid']}:
                        conn.sendall(b'{"ok":false,"error":"peer_denied"}\n');continue
                    try:
                        data=b''
                        while not data.endswith(b'\n'):
                            chunk=conn.recv(4096)
                            if not chunk:raise ValueError('incomplete')
                            data+=chunk
                            if len(data)>49152:raise ValueError('budget')
                        body=json.loads(data);op=body.get('op')
                        if op in {'cancel','request-status'}:
                            if set(body)!={'op','request_id'} or type(body['request_id']) is not str:raise Rejected('request_shape')
                            result=operations.cancel(body['request_id']) if op=='cancel' else operations.get(body['request_id'])
                            reply={'ok':True,'result':result}
                            if op=='cancel':
                                reply.update(cancel_accepted=result['state']=='CANCEL_REQUESTED',cancel_complete=result['state'] in {'CANCELLED','ROLLED_BACK'})
                        elif op=='submit':
                            Operations.identity(body)
                            # Deduplicated requests remain readable while the executor is busy.
                            try:existing=operations.get(body['request_id'])
                            except Rejected:existing=None
                            if existing:
                                if existing['digest']!=Operations.identity(body):raise Rejected('request_conflict')
                                reply={'ok':True,'result':existing,'created':False}
                            else:
                                if not guard.acquire(False):raise Rejected('busy')
                                try:
                                    result,created=operations.admit(body)
                                    if created:start_work(operations,body,work,config.get('fail_dispatch',False))
                                    else:guard.release()
                                except Exception:guard.release();raise
                                reply={'ok':True,'result':result,'created':created}
                        else:
                            if op=='execute' or op=='activate' and not config.get('legacy_api',False):raise Rejected('use_submit')
                            if not guard.acquire(False):raise Rejected('busy')
                            try:reply=execute(body,uid)
                            finally:guard.release()
                    except Exception as error:
                        reply={'ok':False,'error':type(error).__name__}
                        if isinstance(error,Rejected):reply['reason']=str(error)
                    try:conn.sendall(json.dumps(reply).encode()+b'\n')
                    except OSError:pass
    finally:os.close(fd)

if __name__=='__main__':serve(sys.argv[1])
