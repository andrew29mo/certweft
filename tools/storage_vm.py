"""Bounded real-service storage faults on a dedicated ext4 loop mount in Linux VM.

Run as root only. Never fills/remounts the host root filesystem. Root-only SQL
allocation triggers force actual SQLITE_FULL under pager quota, not RAISE().
"""
import threading,contextlib,errno,hashlib,html,json,os,pathlib,pwd,shutil,signal,socket,sqlite3,ssl,subprocess,sys,tempfile,time
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
from certweft.core import Writer,run,fingerprint
from certweft.operations import Operations
from tools.executor_vm import hashes
P=pathlib.Path(__file__).resolve().parents[1]

def alive(pid,start=None):
    try:
        raw=pathlib.Path('/proc',str(pid),'stat').read_text();fields=raw[raw.rfind(')')+2:].split()
        return fields[0]!='Z' and (start is None or fields[19]==start)
    except FileNotFoundError:return False

def call(endpoint,body):
    # Only expected socket failures are transport results. Local helper failure
    # (imports/runuser/JSON/etc.) must fail the fixture, never stand in for EOF.
    code="""import json,socket,sys
sent=False
try:
 with socket.socket(socket.AF_UNIX) as s:
  s.settimeout(3);s.connect(sys.argv[1]);s.sendall(sys.argv[2].encode()+b'\\n');sent=True;out=b''
  while not out.endswith(b'\\n'):
   part=s.recv(4096)
   if not part:raise EOFError('closed')
   out+=part
  reply=json.loads(out)
except (OSError,EOFError) as error:
 reply={'ok':False,'transport_unavailable':True,'request_sent':sent,'transport_error':type(error).__name__,'errno':getattr(error,'errno',None)}
print(json.dumps(reply))
"""
    result=subprocess.run(['runuser','-u','nobody','--',sys.executable,'-c',code,str(endpoint),json.dumps(body)],cwd=P,capture_output=True,timeout=4)
    if result.returncode:raise RuntimeError('controller_helper_failed')
    return json.loads(result.stdout)

def scenario(kind,phase,check_gate=False,lifecycle_mode=None):
    work=pathlib.Path(tempfile.mkdtemp(prefix='cw-storage-',dir='/var/tmp'));os.chmod(work,0o711)
    image=work/'disk.img';mount=work/'store';mount.mkdir(mode=0o700)
    parent=None;ngpid=None;ngworkers=[];mounted=False;bound=False;child=None;loop=None
    result={'fault':kind,'phase':phase,'ext4_image_bytes':32*1024*1024};t=time.monotonic()
    try:
        with image.open('wb') as f:f.truncate(32*1024*1024)
        run(['mkfs.ext4','-q','-F','-m','0',image]);run(['mount','-o','loop',image,mount]);mounted=True;os.chmod(mount,0o700)
        loop=run(['findmnt','-n','-o','SOURCE','--target',mount]).decode().strip()
        key=work/'key';cakey=work/'ca-key';ca=work/'ca.pem';old=work/'old.pem';new=work/'new.pem';csr=work/'req';ext=work/'ext'
        for k in [key,cakey]:run(['openssl','ecparam','-name','prime256v1','-genkey','-noout','-out',k])
        run(['openssl','req','-new','-x509','-key',cakey,'-subj','/CN=Storage Fixture','-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=keyCertSign,cRLSign','-out',ca])
        run(['openssl','req','-new','-key',key,'-subj','/CN=localhost','-out',csr])
        ext.write_text('subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\nbasicConstraints=critical,CA:FALSE\n')
        for cert,serial in [(old,'1'),(new,'2')]:run(['openssl','x509','-req','-in',csr,'-CA',ca,'-CAkey',cakey,'-sha256','-set_serial',serial,'-days','1','-extfile',ext,'-out',cert])
        with socket.socket() as s:s.bind(('127.0.0.1',0));port=s.getsockname()[1]
        conf=work/'nginx.conf';w=Writer(mount,'/usr/sbin/nginx',conf,ca,key,'localhost','127.0.0.1',port);w.initialize(old);Operations(mount).initialize()
        baseline=w.status();pointer=os.readlink(mount/'active.conf')
        conf.write_text(f'pid {work}/nginx.pid; error_log {work}/nginx.log; events {{}} http {{ access_log off; server {{ listen 127.0.0.1:{port} ssl; server_name localhost; include {mount}/active.conf; location = /health {{ return 200 "ok"; }} }} }}')
        run(['/usr/sbin/nginx','-c',conf]);ngpid=int((work/'nginx.pid').read_text());raw=pathlib.Path('/proc',str(ngpid),'stat').read_text()
        config={'writer':{'root':str(mount),'nginx':'/usr/sbin/nginx','conf':str(conf),'ca':str(ca),'key':str(key),'host':'localhost','ip':'127.0.0.1','port':port},'controller_uid':pwd.getpwnam('nobody').pw_uid,'socket':str(work/'writer.sock'),'lease':str(work/'lifetime.lock'),'master':{'pid':ngpid,'start':raw[raw.rfind(')')+2:].split()[19]},'executor_inventory':str(work/'executors.jsonl')}
        if phase!='pre':config.update(pause_at='preparing' if phase=='prepare' else 'confirmed',marker=str(work/'marker.json'))
        if phase=='cancel_race':config['storage_latch_marker']=str(work/'latch.json')
        if phase=='cancel_unrecorded':config['unrecorded_storage_marker']=str(work/'unrecorded.json')
        if kind=='sqlite_full':
            with contextlib.closing(sqlite3.connect(mount/'journal.db')) as db, db:
                db.execute('CREATE TABLE quota_probe(data BLOB)')
                when={'pre':"BEFORE INSERT ON requests",'prepare':"BEFORE INSERT ON state WHEN json_extract(NEW.data,'$.state')='APPLYING'",'post':"BEFORE UPDATE ON requests WHEN NEW.state='COMMITTED'",'cancel':"BEFORE UPDATE ON requests WHEN NEW.state='CANCEL_REQUESTED'",'cancel_race':"BEFORE UPDATE ON requests WHEN NEW.state='CANCEL_REQUESTED'",'cancel_unrecorded':"BEFORE UPDATE ON requests WHEN NEW.state='CANCEL_REQUESTED'"}[phase]
                db.execute('CREATE TRIGGER allocate_quota '+when+' BEGIN INSERT INTO quota_probe VALUES(zeroblob(65536)); END')
                if phase=='cancel_unrecorded':db.execute('CREATE TRIGGER fail_health BEFORE UPDATE ON health BEGIN INSERT INTO quota_probe VALUES(zeroblob(65536)); END')
                config['sqlite_max_pages']=db.execute('PRAGMA page_count').fetchone()[0]+1
            result['pager_max_pages']=config['sqlite_max_pages'];result['allocation_bytes']=65536
        if lifecycle_mode=='stop-sync-eio':config.update(gate_stop_sync_eio=True,gate_stop_sync_marker=str(work/'stop-sync.json'))
        cfg=work/'config';cfg.write_text(json.dumps(config))
        log=(work/'service.log').open('wb')
        parent=subprocess.Popen([sys.executable,'-m','certweft.service',str(cfg)],cwd=P,stdout=log,stderr=subprocess.STDOUT);log.close()
        for _ in range(120):
            if parent.poll() is not None:raise AssertionError('service_startup')
            if (work/'writer.sock').exists():break
            time.sleep(.025)
        else:raise AssertionError('no_socket')
        job={'op':'submit','request_id':'storage-'+kind+'-'+phase,'certificate':new.read_text(),'epoch':baseline['epoch'],'revision':baseline['revision']}
        def wire():
            ctx=ssl.create_default_context(cafile=str(ca))
            with socket.create_connection(('127.0.0.1',port),2) as raw:
                with ctx.wrap_socket(raw,server_hostname='localhost') as tls:
                    assert not tls.session_reused
                    digest=hashlib.sha256(tls.getpeercert(True)).hexdigest()
                    tls.sendall(b'GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n');assert tls.recv(1024).startswith(b'HTTP/1.1 200 ')
            if digest==fingerprint(old):return 'baseline'
            if digest==fingerprint(new):return 'candidate'
            raise AssertionError('unexpected_wire_leaf')
        assert wire()=='baseline'
        def fault():
            nonlocal bound
            if kind=='readonly':
                run(['mount','--bind',mount,mount]);bound=True
                run(['mount','-o','remount,bind,ro',mount])
            elif kind=='enospc':
                filled=0
                with (mount/'filler').open('wb',buffering=0) as f:
                    try:
                        while True:filled+=f.write(b'x'*65536)
                    except OSError as e:assert e.errno==errno.ENOSPC
                    os.fsync(f.fileno())
                # Consume trailing partial blocks too, until even 1 byte fails.
                try:
                    with (mount/'last-blocks').open('wb',buffering=0) as f:
                        while True:f.write(b'x'*4096)
                except OSError as e:assert e.errno==errno.ENOSPC
                result['filled_bytes']=filled
            if kind!='sqlite_full':
                try:
                    with (mount/'fault-probe').open('wb',buffering=0) as f:f.write(b'x'*4096);os.fsync(f.fileno())
                except OSError as e:
                    assert e.errno=={'enospc':errno.ENOSPC,'readonly':errno.EROFS}[kind];result['observed_errno']=e.errno
                else:raise AssertionError('fault_not_real')
                result['mount_options']=run(['findmnt','-n','-o','OPTIONS','--target',mount]).decode().strip()
        def memory(pid):
            return {line.split(':')[0]:line.split(':')[1].strip() for line in pathlib.Path('/proc',str(pid),'status').read_text().splitlines() if line.startswith(('VmRSS:','VmHWM:'))}
        if check_gate and phase=='pre':
            from certweft.gate import Gate
            from tools.executor_vm import request
            gate_before=Gate(mount).read()
            competing=subprocess.run([sys.executable,'-m','certweft.service',str(cfg)],cwd=P,capture_output=True,timeout=4)
            assert competing.returncode==73 and Gate(mount).read()==gate_before
            running_prepare=request(config['socket'],{'op':'prepare-recovery',**Gate.token(gate_before)})
            assert not running_prepare['ok'] and running_prepare['reason']=='not_recovery_required'
            committed=call(config['socket'],{**job,'request_id':'healthy-smoke','certificate':old.read_text()});assert committed['created']
            for _ in range(150):
                terminal=call(config['socket'],{'op':'request-status','request_id':'healthy-smoke'})
                if terminal.get('ok') and terminal['result']['state']=='COMMITTED' and not request(config['socket'],{'op':'recovery-status'})['executor_busy']:break
                time.sleep(.025)
            else:raise AssertionError('healthy_activation_not_committed')
            assert wire()=='baseline'
            parent.terminate();parent.wait(3);assert parent.returncode==0 and Gate(mount).read()['state']=='STOPPED'
            pathlib.Path(config['socket']).unlink(missing_ok=True)
            log=(work/'healthy-restart.log').open('wb');parent=subprocess.Popen([sys.executable,'-m','certweft.service',str(cfg)],cwd=P,stdout=log,stderr=subprocess.STDOUT);log.close()
            for _ in range(120):
                if parent.poll() is not None:raise AssertionError('clean_restart_failed')
                if pathlib.Path(config['socket']).exists():break
                time.sleep(.025)
            now=Gate(mount).read();assert now['state']=='RUNNING' and now['epoch']!=gate_before['epoch']
            baseline=w.status();pointer=os.readlink(mount/'active.conf');job.update(epoch=baseline['epoch'],revision=baseline['revision'])
            result['clean_lifecycle']={'normal_activation_committed':True,'graceful_stop_certified':True,'clean_restart_new_epoch':True,'competing_writer_rejected_without_gate_mutation':True}
        if lifecycle_mode:
            from certweft.gate import Gate
            from tools.executor_vm import request
            authority=Gate(mount).read()
            if phase!='pre':
                assert call(config['socket'],job)['created']
                for _ in range(150):
                    if (work/'marker.json').exists():child=json.loads((work/'marker.json').read_text())['pid'];break
                    time.sleep(.02)
                else:raise AssertionError('shutdown_checkpoint_missing')
                assert alive(child)
            before_wire=wire();saved_pointer=os.readlink(mount/'active.conf');saved_versions={p.name for p in mount.glob('v-*')}
            delivered=signal.SIGINT if lifecycle_mode=='sigint' else signal.SIGTERM
            os.kill(parent.pid,delivered);parent.wait(4)
            if child:assert not alive(child)
            stopped=Gate(mount).read()
            if lifecycle_mode=='stop-sync-eio':
                assert parent.returncode!=0 and stopped['state']=='STOPPED' and not Gate(mount).certified(stopped)
                diagnostic=json.loads((work/'stop-sync.json').read_text());assert diagnostic['errno']==errno.EIO
                result['injected_failure']={'point':'primary STOPPED directory-sync','errno':errno.EIO,'physical_failure':False}
            else:assert parent.returncode==0 and stopped['state']=='RUNNING'
            assert wire()==before_wire and os.readlink(mount/'active.conf')==saved_pointer
            saved_journal=hashlib.sha256((mount/'journal.db').read_bytes()).hexdigest()
            cfg.write_text(json.dumps({k:v for k,v in config.items() if k not in {'pause_at','gate_stop_sync_eio','gate_stop_sync_marker'}}))
            for attempt in range(2):
                pathlib.Path(config['socket']).unlink(missing_ok=True)
                log=(work/('shutdown-restart-'+str(attempt)+'.log')).open('wb');parent=subprocess.Popen([sys.executable,'-m','certweft.service',str(cfg)],cwd=P,stdout=log,stderr=subprocess.STDOUT);log.close()
                for _ in range(120):
                    if parent.poll() is not None:raise AssertionError('shutdown_gate_restart_failed')
                    if pathlib.Path(config['socket']).exists():break
                    time.sleep(.025)
                current=request(config['socket'],{'op':'recovery-status'})['gate'];assert current['state']=='RECOVERY_REQUIRED'
                refused=call(config['socket'],{**job,'request_id':'shutdown-restart-'+str(attempt)})
                assert not refused.get('ok') and refused.get('reason')=='recovery_required'
                stale=request(config['socket'],{'op':'prepare-recovery',**Gate.token(authority)})
                assert not stale['ok'] and stale['reason']=='stale_gate_authority'
                assert hashlib.sha256((mount/'journal.db').read_bytes()).hexdigest()==saved_journal
                assert os.readlink(mount/'active.conf')==saved_pointer and {p.name for p in mount.glob('v-*')}==saved_versions and wire()==before_wire
                # Healthy idle RECOVERY_REQUIRED must also survive both signals.
                os.kill(parent.pid,signal.SIGINT if attempt else signal.SIGTERM);parent.wait(4)
                assert Gate(mount).read()['state']=='RECOVERY_REQUIRED'
            result.update(lifecycle_mode=lifecycle_mode,parent_signal='SIGINT' if delivered==signal.SIGINT else 'SIGTERM',active_executor_exited=child is not None,shutdown_record=stopped['state'],restarts_blocked=2,idle_recovery_required_survives_both_signals=True,no_tls_pointer_or_version_changes=True,journal_preserved_across_restarts=True,passed=True)
            return result
        result['service_memory_before_fault']=memory(parent.pid)
        if phase=='pre':
            fault();reply=call(config['socket'],job);result['initial_reply']=reply
            assert not reply.get('ok') and not reply.get('created')
            assert os.readlink(mount/'active.conf')==pointer and wire()=='baseline'
        else:
            accepted=call(config['socket'],job);assert accepted.get('ok') and accepted.get('created')
            for _ in range(150):
                if (work/'marker.json').exists():child=json.loads((work/'marker.json').read_text())['pid'];break
                time.sleep(.02)
            else:raise AssertionError('confirmed_checkpoint_missing')
            if phase=='prepare':
                assert wire()=='baseline' and os.readlink(mount/'active.conf')==pointer
                result['baseline_observed_before_fault']=True
            else:
                assert wire()=='candidate';result['candidate_observed_before_fault']=True
            if check_gate:
                from certweft.gate import Gate
                from tools.executor_vm import request
                snapshot=Gate(mount).read()
                busy=request(config['socket'],{'op':'prepare-recovery',**Gate.token(snapshot)})
                assert not busy['ok'] and busy['reason']=='busy'
                competing=subprocess.run([sys.executable,'-m','certweft.service',str(cfg)],cwd=P,capture_output=True,timeout=4)
                assert competing.returncode==73 and Gate(mount).read()==snapshot
                result['active_executor_fencing']={'prepare_denied_while_busy':True,'competing_writer_rejected':True,'gate_unchanged':True}
            result['executor_memory_at_checkpoint']=memory(child)
            fault()
            cancellation=None;answers=[];errors=[]
            if phase=='cancel_race':
                def cancel_in_parallel():
                    try:answers.append(call(config['socket'],{'op':'cancel','request_id':job['request_id']}))
                    except Exception as error:errors.append(type(error).__name__)
                cancellation=threading.Thread(target=cancel_in_parallel);cancellation.start()
                for _ in range(120):
                    if (work/'latch.json').exists():break
                    time.sleep(.01)
                else:raise AssertionError('fault_latch_checkpoint_missing')
                assert json.loads((work/'latch.json').read_text())['pid']==parent.pid
                os.kill(child,signal.SIGCONT);time.sleep(.1)
                with contextlib.closing(sqlite3.connect('file:'+str(mount/'journal.db')+'?mode=ro',uri=True)) as observer:
                    assert observer.execute('SELECT state FROM requests WHERE id=?',(job['request_id'],)).fetchone()[0]=='RUNNING'
                    assert observer.execute('SELECT state FROM health').fetchone()[0]=='HEALTHY'
                assert alive(child);result['executor_resumed_while_fault_handler_paused']=True
                os.kill(parent.pid,signal.SIGCONT);cancellation.join(3);assert not cancellation.is_alive() and not errors and answers
                reply=answers[0]
            elif phase in {'cancel','cancel_unrecorded'}:reply=call(config['socket'],{'op':'cancel','request_id':job['request_id']})
            if phase in {'cancel','cancel_race','cancel_unrecorded'}:
                result['cancel_reply']=reply
                assert not reply.get('ok') and not reply.get('cancel_accepted') and not reply.get('cancel_complete')
                if reply.get('transport_unavailable'):assert reply['request_sent'], 'cancel_not_sent'
            if phase!='cancel_race' and alive(child):os.kill(child,signal.SIGCONT)
            for _ in range(300):
                if not alive(child):break
                time.sleep(.025)
            else:raise AssertionError('executor_stuck')
        # New identity must be rejected/unavailable even when baseline was restored.
        retry=call(config['socket'],{**job,'request_id':'new-update'});result['new_update_reply']=retry
        assert not retry.get('ok') and not retry.get('created')
        with contextlib.closing(sqlite3.connect('file:'+str(mount/'journal.db')+'?mode=ro',uri=True)) as db:
            state=json.loads(db.execute('SELECT data FROM state').fetchone()[0])
            row=db.execute('SELECT state,result FROM requests WHERE id=?',(job['request_id'],)).fetchone()
            health=db.execute('SELECT state FROM health WHERE id=1').fetchone()[0]
            assert state['committed']==baseline['committed']
            assert not db.execute("SELECT 1 FROM requests WHERE id='new-update'").fetchone()
            if row:assert row[0] not in {'COMMITTED','ROLLED_BACK','CANCELLED'}
            if phase=='pre':assert row is None
            if phase=='prepare':assert os.readlink(mount/'active.conf')==pointer
            result.update(core_state=state['state'],request_state=row[0] if row else None,request_result=json.loads(row[1]) if row and row[1] else None,storage_health=health)
        result['wire_after']=wire();result['service_exit']=parent.poll()
        if kind=='sqlite_full' and phase!='cancel_unrecorded':
            assert health=='STORAGE_FAILED'
            assert state['state']=='READY'
            if phase!='pre':assert row[0]=='DEGRADED'
            codes=[(result.get('initial_reply') or {}).get('sqlite_error'),(result.get('cancel_reply') or {}).get('sqlite_error'),(result.get('request_result') or {}).get('sqlite_error')]
            if phase not in {'cancel','cancel_race'}:assert 'SQLITE_FULL' in codes
            else:assert result['cancel_reply'].get('sqlite_error')=='SQLITE_FULL'
            assert result['wire_after']=='baseline'
            parent.terminate();parent.wait(3)
            log=(work/'service-restart.log').open('wb')
            parent=subprocess.Popen([sys.executable,'-m','certweft.service',str(cfg)],cwd=P,stdout=log,stderr=subprocess.STDOUT);log.close()
            for _ in range(120):
                if parent.poll() is not None:raise AssertionError('latched_restart_failed')
                response=call(config['socket'],{**job,'request_id':'after-restart'})
                if response.get('reason')=='recovery_required':break
                time.sleep(.025)
            else:raise AssertionError('restart_lost_storage_latch')
            result['restart_still_blocks_new_updates']=True
        else:
            # The service cannot persist its health latch on a broken filesystem.
            parent.wait(3);assert parent.returncode==75;result['service_exit']=75
            if phase=='cancel_unrecorded':
                assert not alive(child) and health=='HEALTHY' and row[0]=='RUNNING'
                result['unrecordable_fault_executor_stopped']=True
                result['unrecorded_fault']=json.loads((work/'unrecorded.json').read_text())
                assert result['unrecorded_fault']['sqlite_error']=='SQLITE_FULL'
                result['restart_after_unrecordable_fault']='see restart-gate validation; full restoration not qualified'
            else:
                # Fault is still active. Startup may bind on no-op metadata;
                # either startup fails, or an actual new submission must fail.
                pathlib.Path(config['socket']).unlink(missing_ok=True)
                log=(work/'fault-restart.log').open('wb')
                parent=subprocess.Popen([sys.executable,'-m','certweft.service',str(cfg)],cwd=P,stdout=log,stderr=subprocess.STDOUT);log.close()
                for _ in range(120):
                    if parent.poll() is not None:break
                    if pathlib.Path(config['socket']).exists():
                        response=call(config['socket'],{**job,'request_id':'fault-restart-update'})
                        assert not response.get('ok') and not response.get('created')
                        result['fault_restart_update_reply']=response;break
                    time.sleep(.025)
                if parent.poll() is None:
                    from certweft.gate import Gate
                    assert Gate(mount).read()['state']=='RECOVERY_REQUIRED'
                    assert result['fault_restart_update_reply'].get('reason')=='recovery_required'
                else:assert parent.returncode!=0
                result['restart_during_fault_refused_updates']=True
                result['fault_restart_exit']=parent.returncode
        if check_gate:
            from certweft.gate import Gate
            from tools.executor_vm import request
            # Repair only the private fault mechanism, without changing journal,
            # active pointer, request rows or execution record.
            if parent.poll() is None:parent.terminate();parent.wait(3)
            saved_gate=Gate(mount).read();saved_wire=wire();saved_pointer=os.readlink(mount/'active.conf');saved_generations={p.name for p in mount.glob('v-*')}
            if bound:run(['umount',mount]);bound=False
            for name in ['filler','last-blocks','fault-probe']:(mount/name).unlink(missing_ok=True)
            with contextlib.closing(sqlite3.connect(mount/'journal.db')) as db, db:
                db.execute('DROP TRIGGER IF EXISTS allocate_quota');db.execute('DROP TRIGGER IF EXISTS fail_health')
                raw_health=db.execute('SELECT state FROM health').fetchone()[0]
            before_journal=hashlib.sha256((mount/'journal.db').read_bytes()).hexdigest()
            # No fixture checkpoint should stop an attempted normal submission.
            cfg.write_text(json.dumps({k:v for k,v in config.items() if k not in {'pause_at','storage_latch_marker','unrecorded_storage_marker'}}))
            log=(work/'repaired-restart.log').open('wb');parent=subprocess.Popen([sys.executable,'-m','certweft.service',str(cfg)],cwd=P,stdout=log,stderr=subprocess.STDOUT);log.close()
            for _ in range(120):
                if parent.poll() is not None:raise AssertionError('repaired_gate_startup')
                try:
                    status=request(config['socket'],{'op':'recovery-status'})
                    if status.get('ok'):break
                except (OSError,EOFError):pass
                time.sleep(.025)
            else:raise AssertionError('no_recovery_endpoint')
            current=status['gate'];assert current['state']=='RECOVERY_REQUIRED' and not status['gate_allows_updates']
            assert os.readlink(mount/'active.conf')==saved_pointer and {p.name for p in mount.glob('v-*')}==saved_generations
            assert hashlib.sha256((mount/'journal.db').read_bytes()).hexdigest()==before_journal
            before_pointer=saved_pointer;before_count=len(saved_generations)
            update=call(config['socket'],{**job,'request_id':'repaired-restart-update'});assert not update.get('ok') and update.get('reason')=='recovery_required'
            authority=lambda value:{'gate_epoch':value['epoch'],'gate_revision':value['revision']}
            stale={'op':'prepare-recovery',**authority(saved_gate)}
            response=request(config['socket'],stale);assert not response['ok'] and response['reason']=='stale_gate_authority'
            denied=call(config['socket'],{'op':'prepare-recovery',**authority(current)});assert not denied['ok'] and denied['reason']=='admin_required'
            assert not call(config['socket'],{'op':'recovery-status'})['ok']
            old_recover=request(config['socket'],{'op':'recover'});assert not old_recover['ok'] and old_recover['reason']=='use_prepare_recovery'
            invalid=request(config['socket'],{'op':'prepare-recovery',**authority(current),'clear_storage':True});assert not invalid['ok']
            prepared=request(config['socket'],{'op':'prepare-recovery',**authority(current)})
            assert prepared['ok'] and prepared['prepared'] and not prepared['updates_enabled'] and not prepared['restored'] and prepared['gate']['state']=='VERIFY_REQUIRED'
            repeated=request(config['socket'],{'op':'prepare-recovery',**authority(current)});assert not repeated['ok'] and repeated['reason']=='stale_gate_authority'
            assert Gate(mount).read()==prepared['gate']
            assert {p.name for p in mount.glob('v-*')}==saved_generations
            assert os.readlink(mount/'active.conf')==before_pointer and len(list(mount.glob('v-*')))==before_count and wire()==saved_wire
            assert hashlib.sha256((mount/'journal.db').read_bytes()).hexdigest()==before_journal
            parent.terminate();parent.wait(3)
            assert Gate(mount).read()['state']=='VERIFY_REQUIRED'
            # A second recovery-only restart invalidates the former root CAS.
            pathlib.Path(config['socket']).unlink(missing_ok=True)
            log=(work/'prepared-restart.log').open('wb');parent=subprocess.Popen([sys.executable,'-m','certweft.service',str(cfg)],cwd=P,stdout=log,stderr=subprocess.STDOUT);log.close()
            for _ in range(120):
                if parent.poll() is not None:raise AssertionError('prepared_restart_failed')
                if pathlib.Path(config['socket']).exists():break
                time.sleep(.025)
            now=request(config['socket'],{'op':'recovery-status'})['gate'];assert now['state']=='RECOVERY_REQUIRED'
            assert os.readlink(mount/'active.conf')==saved_pointer and {p.name for p in mount.glob('v-*')}==saved_generations
            response=request(config['socket'],{'op':'prepare-recovery',**authority(prepared['gate'])});assert not response['ok'] and response['reason']=='stale_gate_authority'
            assert not call(config['socket'],{**job,'request_id':'second-restart-update'})['ok']
            assert wire()==saved_wire and hashlib.sha256((mount/'journal.db').read_bytes()).hexdigest()==before_journal
            result['restart_gate']={'repaired_storage_still_blocks':True,'journal_byte_identical_after_repair':True,'no_tls_or_pointer_changes':True,'root_only_prepare':True,'stale_and_duplicate_cas_rejected':True,'second_restart_invalidates_old_cas':True,'prepared_never_enables_updates':True,'raw_health_before_repaired_restart':raw_health,'wire_preserved':saved_wire}
        result['passed']=True
    finally:
        cleanup=True
        if child and alive(child):os.kill(child,signal.SIGKILL)
        if parent and parent.poll() is None:
            os.kill(parent.pid,signal.SIGCONT);parent.terminate()
        if parent:
            try:parent.wait(3)
            except subprocess.TimeoutExpired:parent.kill();parent.wait();cleanup=False
        tracked=[]
        if (work/'executors.jsonl').exists():tracked=[json.loads(x) for x in (work/'executors.jsonl').read_text().splitlines()]
        for entry in tracked:
            if alive(entry['pid'],entry['start']):os.kill(entry['pid'],signal.SIGKILL)
        if ngpid:
            children=pathlib.Path('/proc',str(ngpid),'task',str(ngpid),'children')
            if children.exists():ngworkers=list(map(int,children.read_text().split()))
            try:run(['/usr/sbin/nginx','-s','quit','-c',work/'nginx.conf'])
            except Exception:cleanup=False
        for _ in range(100):
            if not any(alive(e['pid'],e['start']) for e in tracked) and not any(alive(p) for p in ([ngpid] if ngpid else [])+ngworkers):break
            time.sleep(.03)
        else:cleanup=False
        if mounted:
            try:
                if bound:run(['umount',mount]);bound=False
                run(['umount',mount]);mounted=False
                assert subprocess.run(['mountpoint','-q',str(mount)]).returncode!=0
                if loop:assert subprocess.run(['losetup',loop],capture_output=True).returncode!=0
            except Exception as error:
                cleanup=False;result['mount_cleanup_error']=type(error).__name__+': '+str(error)
        result.update(cleanup_verified=cleanup,tracked_executors=len(tracked),elapsed_seconds=time.monotonic()-t)
        if not mounted and cleanup:shutil.rmtree(work)
        if not cleanup:raise AssertionError('fixture_cleanup_failed: '+json.dumps(result))
    return result

def main():
    if os.geteuid()!=0:raise PermissionError('isolated VM root required')
    os.umask(0o077);source=hashes();out=P/'evidence/storage.json';out.parent.mkdir(exist_ok=True)
    if out.exists():
        archive=P/'evidence/storage-attempts';archive.mkdir(exist_ok=True);shutil.copyfile(out,archive/(str(time.time_ns())+'.json'))
    def publish(d):
        text=json.dumps(d,indent=2);out.with_suffix('.html').write_text('<!doctype html><meta charset="utf-8"><pre>'+html.escape(text)+'</pre>');out.write_text(text)
    report={'passed':False,'status':'in_progress','cases':[],'scope':'formal certweft.service + executor; Nginx; ext4 loop filesystem in isolated Linux VM','untested':['physical medium failures','fsync failure injection','power loss','VM reboot','persistent systemd deployment','controlled DEGRADED repair','automatic quota/history recycling']};publish(report)
    try:
        for kind in ['enospc','readonly','sqlite_full']:
            for phase in ['pre','prepare','post','cancel']+(['cancel_race','cancel_unrecorded'] if kind=='sqlite_full' else []):
                try:result=scenario(kind,phase)
                except Exception as error:
                    report['cases'].append({'fault':kind,'phase':phase,'passed':False,'error':type(error).__name__+': '+str(error)});raise
                report['cases'].append(result);publish(report)
        report['passed']=True;report['status']='completed'
    except Exception as e:
        import traceback;traceback.print_exc();report['error']=type(e).__name__+': '+str(e);report['status']='failed'
    report['environment']={'python':sys.version.split()[0],'sqlite':sqlite3.sqlite_version,'openssl':ssl.OPENSSL_VERSION,'kernel':os.uname().release,'machine':os.uname().machine}
    report['source_sha256']=source;report['source_unchanged']=source==hashes();report['passed']=report['passed'] and report['source_unchanged'];publish(report)
    print(json.dumps({'passed':report['passed'],'cases':len(report['cases']),'error':report.get('error')}));return 0 if report['passed'] else 1
if __name__=='__main__':sys.exit(main())
