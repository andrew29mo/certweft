"""Fixed local privileged writer. One bounded request/executor at a time."""
import fcntl,json,os,signal,socket,stat,struct,subprocess,sys,threading,time
from .operations import Operations,decision
from .gate import Gate
from .recovery import RecoveryStore
from . import storage
from .opening import require_updates
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

def reap_executor(child,terminate):
    """Reap this owned session, including pipe-holding descendants on error."""
    if terminate:
        try:os.killpg(child.pid,signal.SIGKILL)
        except ProcessLookupError:pass
    try:child.wait(timeout=3)
    except subprocess.TimeoutExpired:os._exit(75)
    for stream in (child.stdin,child.stdout,child.stderr):
        if stream is not None:
            try:stream.close()
            except OSError:pass

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
        # Persist uncertainty before metadata writes or exposing any endpoint.
        gate=Gate(root)
        if config.get('gate_stop_sync_eio'):
            def gate_checkpoint(point,state):
                if point=='directory-sync' and state['reason']=='clean_stop':
                    import errno
                    if config.get('gate_stop_sync_marker'):Path(config['gate_stop_sync_marker']).write_text(json.dumps({'point':point,'errno':errno.EIO}))
                    raise OSError(errno.EIO,'root-fixture clean-stop directory sync')
            gate.checkpoint=gate_checkpoint
        with decision(root/'journal.db'):session=gate.start()
        config['gate_authority']=Gate.token(session)
        operations=Operations(root,config.get('sqlite_max_pages'))
        if session['state']=='RUNNING':operations.initialize()
        recovery=RecoveryStore(root);recovery.initialize()
        if recovery.reconcile() and session['state']=='RUNNING':
            with decision(root/'journal.db'):session=gate.block(config['gate_authority'])
            config['gate_authority']=Gate.token(session)
        active=[None];process_lock=threading.RLock();launch_stopped=[False]
        def unrecorded_storage(error):
            # Called while the metadata decision barrier is still held. No
            # orphaned executor may race COMMIT after an unrecordable fault.
            import signal
            if config.get('unrecorded_storage_marker'):
                try:Path(config['unrecorded_storage_marker']).write_text(json.dumps(storage.detail(error)))
                except OSError:pass
            # Launch/register and fatal cleanup are one critical section;
            # cleanup cannot miss a Popen that has not yet entered active[0].
            with process_lock:
                child=active[0]
                if child is not None:reap_executor(child,True)
                os._exit(75)
        operations.unrecorded_storage=unrecorded_storage
        if config.get('storage_latch_marker'):
            def pause_storage_latch():
                import signal
                marker=Path(config['storage_latch_marker']);pending=marker.with_suffix('.pending')
                pending.write_text(json.dumps({'pid':os.getpid(),'point':'before-storage-latch'}));os.replace(pending,marker)
                os.kill(os.getpid(),signal.SIGSTOP)
            operations.before_storage_latch=pause_storage_latch
        guard=threading.Lock()
        def execute(body,uid,module='certweft.executor'):
            child=None;completed=False
            try:
                with process_lock:
                    if launch_stopped[0]:raise Rejected('service_stopping')
                    if active[0] is not None:raise Rejected('executor_still_registered')
                    child=subprocess.Popen([sys.executable,'-m',module,str(fd)],
                        start_new_session=True,pass_fds=(fd,),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                    active[0]=child
                if config.get('executor_inventory'):
                    raw=Path('/proc',str(child.pid),'stat').read_text()
                    record=json.dumps({'pid':child.pid,'start':raw[raw.rfind(')')+2:].split()[19]})+'\n'
                    inventory=os.open(config['executor_inventory'],os.O_WRONLY|os.O_CREAT|os.O_APPEND|os.O_NOFOLLOW,0o600)
                    try:os.write(inventory,record.encode())
                    finally:os.close(inventory)
                try:out,err=child.communicate(json.dumps({'body':body,'peer_uid':uid,'config':config}).encode(),timeout=20)
                except subprocess.TimeoutExpired:raise TimeoutError('executor_timeout')
                if child.returncode!=0 or len(out)>16384:raise RuntimeError('executor_failure')
                result=json.loads(out);completed=True
                return result
            finally:
                if child is not None:
                    with process_lock:
                        reap_executor(child,not completed or child.poll() is None)
                        if active[0] is child:active[0]=None
        # A dirty session is never automatically repaired or replayed at startup.
        # Preserve pending/core evidence for the future verification backend.
        if session['state']=='RUNNING' and operations.pending():
            with decision(root/'journal.db'):session=gate.block(config['gate_authority'])
            config['gate_authority']=Gate.token(session)
        def work(body):
            try:
                reply=execute({'op':'execute',**{k:v for k,v in body.items() if k!='op'}},0)
                if storage.failed(reply):operations.latch_storage(reply)
                if not reply.get('ok'):operations.finish(body['request_id'],'DEGRADED',{'executor_error':reply.get('error'),'sqlite_error':reply.get('sqlite_error'),'errno':reply.get('errno')})
            except Exception as error:
                try:
                    if storage.failed(error):operations.latch_storage(error)
                    operations.finish(body['request_id'],'DEGRADED',{'executor_error':type(error).__name__})
                except Exception:unrecorded_storage(error)
            finally:guard.release()
        def work_verification(body):
            try:
                reply=execute({'op':'run-verification','request_id':body['request_id']},0,'certweft.recovery_executor')
                if reply.get('ok') and reply.get('result',{}).get('state')=='OPENED':
                    with decision(root/'journal.db'):
                        authority=reply['result']['result']['opened_gate']
                        try:
                            from .recovery import operation_remaining
                            operation_remaining(reply['result']);require_updates(root,authority)
                            operation_remaining(reply['result'])
                            config['gate_authority']=authority
                        except Exception:
                            current=gate.read()
                            if Gate.token(current)==authority and current['state']=='RUNNING':gate.block(authority)
                            raise
                if not reply.get('ok'):recovery.finish(body['request_id'],'FAILED',{'storage_verified':False,'updates_enabled':False,'restored':False,'error':reply.get('error'),'sqlite_error':reply.get('sqlite_error'),'errno':reply.get('errno')})
            except Exception as error:
                try:recovery.finish(body['request_id'],'FAILED',{'storage_verified':False,'updates_enabled':False,'restored':False,'error':type(error).__name__})
                except Exception:unrecorded_storage(error)
            finally:guard.release()
        def readiness_checkpoint(budget):
            # Root-owned VM fault configuration only; never a request field.
            target=config.get('opening_readiness_expiry_marker')
            if target and not Path(target).exists():
                from . import deadlines
                left=(budget['expires_boot_ns']-deadlines.now_ns())/1e9
                if left>0:time.sleep(left+.02)
                Path(target).write_text(json.dumps({'point':'after-pair-validation','expiry_crossed':deadlines.now_ns()>budget['expires_boot_ns']}))
        stopping=threading.Event()
        previous={sig:signal.getsignal(sig) for sig in [signal.SIGTERM,signal.SIGINT]}
        for sig in previous:signal.signal(sig,lambda *_:stopping.set())
        endpoint=Path(config['socket'])
        if endpoint.exists():endpoint.unlink()
        with socket.socket(socket.AF_UNIX) as server:
            server.bind(str(endpoint));os.chown(endpoint,config['controller_uid'],-1);os.chmod(endpoint,0o600)
            server.listen(4);server.settimeout(.2)
            while not stopping.is_set():
                try:conn,_=server.accept()
                except socket.timeout:continue
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
                        if op in {'verify-storage','recover-certificate','reconcile-closed','prepare-opening','prepare-release','open-updates','recovery-request-status'}:
                            if uid!=0:raise Rejected('admin_required')
                            if op=='recovery-request-status':
                                if set(body)!={'op','request_id'} or type(body['request_id']) is not str:raise Rejected('request_shape')
                                reply={'ok':True,'result':recovery.get(body['request_id']),'historical':True,'updates_enabled':False,'restored':False}
                            else:
                                digest=RecoveryStore.identity(body)
                                try:existing=recovery.get(body['request_id'])
                                except Rejected:existing=None
                                if existing:
                                    if existing['digest']!=digest:raise Rejected('request_conflict')
                                    reply={'ok':True,'result':existing,'created':False,'historical':True,'updates_enabled':False,'restored':False}
                                else:
                                    if not guard.acquire(False):raise Rejected('busy')
                                    try:
                                        result,created=recovery.admit(body,Writer(**config['writer']))
                                        if not created:guard.release()
                                        else:
                                            try:threading.Thread(target=work_verification,args=(body,),daemon=True).start()
                                            except Exception:
                                                recovery.finish(body['request_id'],'FAILED',{'storage_verified':False,'updates_enabled':False,'restored':False,'error':'dispatch_failed'});raise
                                    except Exception:guard.release();raise
                                    reply={'ok':True,'result':result,'created':created,'updates_enabled':False,'restored':False}
                        elif op in {'recovery-status','prepare-recovery','recover'}:
                            if uid!=0:raise Rejected('admin_required')
                            if op=='recover':raise Rejected('use_prepare_recovery')
                            fields={'op'} if op=='recovery-status' else {'op','gate_epoch','gate_revision'}
                            if set(body)!=fields:raise Rejected('request_shape')
                            if op=='prepare-recovery':
                                if type(body['gate_epoch']) is not str or type(body['gate_revision']) is not int:raise Rejected('authority_shape')
                                if not guard.acquire(False):raise Rejected('busy')
                                try:
                                    with decision(root/'journal.db'):
                                        current=gate.prepare({k:body[k] for k in ['gate_epoch','gate_revision']})
                                finally:guard.release()
                                reply={'ok':True,'prepared':True,'updates_enabled':False,'restored':False,'gate':current}
                            else:
                                current=gate.read()
                                from .reconciliation import completion_recorded
                                journal_ready=not guard.locked() and completion_recorded(root,current,recovery)
                                from .opening import ready_closed
                                opening_ready=not guard.locked() and ready_closed(root,current,recovery,readiness_checkpoint)
                                from .release import ready_closed as release_ready_closed
                                release_ready=not guard.locked() and release_ready_closed(root,current)
                                updates_allowed=False
                                if current['state']=='RUNNING':
                                    try:require_updates(root,config['gate_authority']);updates_allowed=True
                                    except (Rejected,OSError):pass
                                reply={'ok':True,'gate':current,'executor_busy':guard.locked(),'gate_allows_updates':updates_allowed,'opening_intent_verified_closed':opening_ready,'release_prepared_closed':release_ready,'storage_health_not_verified':not journal_ready,'journal_prepared_closed':journal_ready,'completion_recorded':recovery.completion_recorded(current)}
                        elif op in {'cancel','request-status'}:
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
                                    require_updates(root,config['gate_authority'])
                                    result,created=operations.admit(body)
                                    if created:start_work(operations,body,work,config.get('fail_dispatch',False))
                                    else:guard.release()
                                except Exception:guard.release();raise
                                reply={'ok':True,'result':result,'created':created}
                        else:
                            if op in {'execute','recover-request'} or op=='activate' and not config.get('legacy_api',False):raise Rejected('use_submit')
                            if not guard.acquire(False):raise Rejected('busy')
                            try:
                                if op!='status':require_updates(root,config['gate_authority'])
                                reply=execute(body,uid)
                                if op=='status':reply['admission_gate']=gate.read()['state']
                            finally:guard.release()
                    except Exception as error:
                        if storage.failed(error):
                            try:operations.latch_storage(error)
                            except Exception:unrecorded_storage(error)
                        reply={'ok':False,'error':type(error).__name__,'sqlite_error':getattr(error,'sqlite_errorname',None),'errno':getattr(error,'errno',None)}
                        if isinstance(error,Rejected):reply['reason']=str(error)
                    try:conn.sendall(json.dumps(reply).encode()+b'\n')
                    except OSError:pass
        for sig,handler in previous.items():signal.signal(sig,handler)
        with process_lock:
            launch_stopped[0]=True
            interrupted=active[0] is not None or guard.locked()
            if active[0] is not None:
                reap_executor(active[0],True);active[0]=None
        # Never certify an exit that interrupted work or an unlaunched request.
        if not interrupted and stopping.is_set() and session['state']=='RUNNING':
            if operations.clean_shutdown_allowed() and Writer(**config['writer']).status()['state']=='READY':
                with decision(root/'journal.db'):gate.stop(config['gate_authority'])
    finally:os.close(fd)

if __name__=='__main__':serve(sys.argv[1])
