"""Formal recovery verifier in isolated VM; shares real storage/gate fixture."""
import contextlib,hashlib,html,json,os,pathlib,shutil,signal,sqlite3,subprocess,sys,time,traceback
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
from certweft import deadlines
from certweft.core import Writer
from certweft.gate import Gate
from certweft.operations import Operations
from tools.executor_vm import hashes,request
P=pathlib.Path(__file__).resolve().parents[1]

def exercise(root,work,config,parent,call,wire,normal_job,fault,mode):
    child=None
    def live(pid):
        try:return pathlib.Path('/proc',str(pid),'stat').read_text().split()[2]!='Z'
        except (FileNotFoundError,ProcessLookupError):return False
    def protect():
        with contextlib.closing(sqlite3.connect('file:'+str(root/'journal.db')+'?mode=ro',uri=True)) as db:
            tables={name:db.execute('SELECT * FROM '+name+' ORDER BY id').fetchall() for name in ['state','health','requests']}
        return hashlib.sha256(repr(tables).encode()).hexdigest(),os.readlink(root/'active.conf'),{p.name for p in root.glob('v-*')},wire()
    def probe_hash():
        with contextlib.closing(sqlite3.connect('file:'+str(root/'journal.db')+'?mode=ro',uri=True)) as db:
            row=db.execute('SELECT value FROM storage_probe').fetchone()
        return hashlib.sha256(row[0]).hexdigest() if row else None
    def inventory():return len((work/'executors.jsonl').read_text().splitlines()) if (work/'executors.jsonl').exists() else 0
    cfg=work/'verification-config'
    frozen={k:v for k,v in config.items() if k not in {'pause_at','storage_latch_marker','unrecorded_storage_marker','gate_stop_sync_eio'}}
    frozen.update(verification_pause_at='before-verification-read' if mode=='malformed-budget' else 'verification-commit' if mode=='expired-finish' else 'probe-written' if mode=='probe-restart' else 'validation-start',verification_marker=str(work/'verification.json'),verification_pause_once=True)
    def start():
        pathlib.Path(config['socket']).unlink(missing_ok=True);(work/'verification.json').unlink(missing_ok=True)
        log=(work/('verification-service-'+str(time.time_ns())+'.log')).open('wb')
        proc=subprocess.Popen([sys.executable,'-m','certweft.service',str(cfg)],cwd=P,stdout=log,stderr=subprocess.STDOUT);log.close()
        for _ in range(120):
            if proc.poll() is not None:raise AssertionError('verification_service_startup')
            if pathlib.Path(config['socket']).exists():return proc
            time.sleep(.025)
        proc.kill();proc.wait();raise AssertionError('verification_endpoint_missing')
    def root_call(body):return request(config['socket'],body)
    def poll(identity):
        for _ in range(200):
            response=root_call({'op':'recovery-request-status','request_id':identity});assert response['ok']
            row=response['result']
            if row['state'] not in {'ACCEPTED','RUNNING'} and not root_call({'op':'recovery-status'})['executor_busy']:return row
            time.sleep(.025)
        raise AssertionError('verification_stuck')
    def expire(timing):
        left=(timing['budget']['expires_boot_ns']-deadlines.now_ns())/1e9
        if left>0:time.sleep(left+.04)
    try:
        parent.terminate();parent.wait(3)
        if mode=='sqlite-full':
            with contextlib.closing(sqlite3.connect(root/'journal.db')) as db, db:
                db.execute('CREATE TABLE verification_pressure(data BLOB)')
                db.execute('CREATE TRIGGER verification_full BEFORE UPDATE ON storage_probe BEGIN INSERT INTO verification_pressure VALUES(zeroblob(65536)); END')
                frozen['sqlite_max_pages']=db.execute('PRAGMA page_count').fetchone()[0]+1
        cfg.write_text(json.dumps(frozen));parent=start()
        current=root_call({'op':'recovery-status'})['gate'];assert current['state']=='RECOVERY_REQUIRED'
        prepared=root_call({'op':'prepare-recovery',**Gate.token(current)});assert prepared['ok'];gate=prepared['gate']
        if mode=='history':
            # Root fixture seeds normal metadata using formal Operations; not a
            # claim of 64 successful certificate rotations or supported rollover.
            ops=Operations(root)
            with contextlib.closing(sqlite3.connect(root/'journal.db')) as db:existing=db.execute('SELECT count(*) FROM requests').fetchone()[0]
            for i in range(64-existing):
                job={'op':'submit','request_id':'seed-'+str(i),'certificate':'pem','epoch':'stale','revision':0}
                ops.admit(job);ops.begin(job['request_id']);ops.finish(job['request_id'],'FAILED',{})
        before=protect();before_probe=probe_hash()
        body={'op':'verify-storage','request_id':'verify-one','timeout_seconds':1 if mode.startswith('expired') or mode=='malformed-budget' else 10,**Gate.token(gate)}
        rejected=call(config['socket'],body);assert not rejected['ok'] and rejected['reason']=='admin_required'
        accepted=root_call(body);assert accepted['ok'] and accepted['created'];initial=accepted['result']
        for _ in range(150):
            if (work/'verification.json').exists():child=json.loads((work/'verification.json').read_text())['pid'];break
            time.sleep(.02)
        else:raise AssertionError('verification_checkpoint_missing')
        assert live(child)
        result={'mode':mode,'root_only':True}
        if mode!='expired-finish':
            duplicate=root_call(body);assert duplicate['ok'] and not duplicate['created'] and duplicate['result']['timing']==initial['timing']
            conflict=root_call({**body,'timeout_seconds':9});assert not conflict['ok'] and conflict['reason']=='request_conflict'
            result.update(duplicate_keeps_original_budget=True,different_parameters_rejected=True)
        else:
            # Independent read bypasses only the advisory metadata lock, not the
            # actual SQLite transaction. Uncommitted success must not be visible.
            with contextlib.closing(sqlite3.connect('file:'+str(root/'recovery.db')+'?mode=ro',uri=True)) as observer:
                assert observer.execute("SELECT state FROM recovery_requests WHERE id='verify-one'").fetchone()[0]=='RUNNING'
            result['paused_after_result_sql_before_commit']=True
        if mode in {'restart','expired-restart','probe-restart'}:
            if mode=='expired-restart':expire(initial['timing'])
            else:assert deadlines.remaining(initial['timing']['budget'])>0
            os.kill(parent.pid,signal.SIGKILL);parent.wait(3)
            with contextlib.closing(sqlite3.connect(root/'recovery.db')) as db:assert db.execute("SELECT state FROM recovery_requests WHERE id='verify-one'").fetchone()[0]=='RUNNING'
            competing=subprocess.run([sys.executable,'-m','certweft.service',str(cfg)],cwd=P,capture_output=True,timeout=3);assert competing.returncode==73
            os.kill(child,signal.SIGKILL)
            for _ in range(100):
                if not live(child):break
                time.sleep(.02)
            else:raise AssertionError('old_verifier_alive')
            count=inventory();frozen.pop('verification_pause_at');cfg.write_text(json.dumps(frozen));parent=start()
            row=poll('verify-one');assert row['state']==('EXPIRED' if mode=='expired-restart' else 'INTERRUPTED')
            assert row['timing']==initial['timing'] and row['target']==initial['target'] and row['probe']==initial['probe']
            assert not root_call(body)['created'] and inventory()==count
            stale=root_call({**body,'request_id':'stale-new'});assert not stale['ok'] and stale['reason']=='stale_gate_authority'
            assert before_probe==probe_hash()
            directory=root/('verify-'+initial['probe'])
            if mode=='probe-restart':
                assert directory.is_dir() and {p.name for p in directory.iterdir()}=={'after'}
                assert (directory/'after').stat().st_size==4096
                result['owned_probe_preserved_after_interruption']=True
            else:assert not directory.exists()
            result.update(restart_preserves_original_timing=True,pending_journal_observed_before_restart=True,old_executor_blocks_takeover=True,no_replayed_verifier=True)
        else:
            if mode.startswith('expired'):expire(initial['timing'])
            if mode=='malformed-budget':
                malformed={**initial['timing'],'budget':None}
                with contextlib.closing(sqlite3.connect(root/'recovery.db')) as db, db:db.execute("UPDATE recovery_requests SET timing=? WHERE id='verify-one'",(json.dumps(malformed),))
                expire(initial['timing'])
            if mode in {'enospc','readonly'}:fault()
            if mode=='bad-schema':
                with contextlib.closing(sqlite3.connect(root/'journal.db')) as db, db:db.execute('DROP TABLE storage_probe')
            if mode=='target-drift':
                with contextlib.closing(sqlite3.connect(root/'journal.db')) as db, db:
                    state=json.loads(db.execute('SELECT data FROM state').fetchone()[0]);state['revision']+=1;db.execute('UPDATE state SET data=?',(json.dumps(state),))
                before=protect()
            if mode=='unknown-probe':
                path=root/('verify-'+initial['probe']);path.mkdir();(path/'unknown').write_text('preserve')
            os.kill(child,signal.SIGCONT)
            if mode in {'enospc','readonly','malformed-budget'}:
                parent.wait(5);assert parent.returncode==75
                with contextlib.closing(sqlite3.connect('file:'+str(root/'recovery.db')+'?mode=ro',uri=True)) as db:
                    raw=db.execute("SELECT state,timing,result FROM recovery_requests WHERE id='verify-one'").fetchone()
                    assert raw[0] in {'ACCEPTED','RUNNING','FAILED'} and raw[0]!='STORAGE_VERIFIED';assert json.loads(raw[1])==({**initial['timing'],'budget':None} if mode=='malformed-budget' else initial['timing'])
                assert not live(child);row={'state':raw[0],'result':None}
                result.update(service_exit=75,no_false_verified_record=True)
                if mode=='malformed-budget':
                    assert raw[0]=='ACCEPTED' and probe_hash()==before_probe and not (root/('verify-'+initial['probe'])).exists()
                    result.update(malformed_budget_rejected_after_original_expiry=True,no_probe_executed=True)
            else:
                row=poll('verify-one')
                expected='EXPIRED' if mode.startswith('expired') else 'FAILED' if mode in {'sqlite-full','bad-schema','target-drift','unknown-probe'} else 'STORAGE_VERIFIED'
                assert row['state']==expected and row['timing']==initial['timing']
                if mode=='sqlite-full':assert row['result']['sqlite_error']=='SQLITE_FULL'
                if mode=='bad-schema':assert row['result']['reason']=='journal_schema'
                if mode=='target-drift':assert row['result']['reason']=='target_drift'
                if mode=='unknown-probe':assert (root/('verify-'+initial['probe'])/'unknown').read_text()=='preserve'
                count=inventory();final_probe=None if mode=='bad-schema' else probe_hash()
                assert not root_call(body)['created'] and count==inventory()
                if mode!='bad-schema':assert probe_hash()==final_probe
                if row['state']=='STORAGE_VERIFIED':assert final_probe!=before_probe and row['result']['storage_verified'] and not row['result']['updates_enabled'] and not row['result']['restored']
                if mode in {'expired-run','sqlite-full','unknown-probe'}:assert final_probe==before_probe
                result['no_replay_of_probe_or_executor']=True
        if mode=='history':
            for i in range(1,16):
                job={**body,'request_id':'capacity-'+str(i)};response=root_call(job)
                assert response.get('created'), {k:response.get(k) for k in ['error','reason','created']}
                assert poll(job['request_id'])['state']=='STORAGE_VERIFIED'
            overflow=root_call({**body,'request_id':'overflow'});assert not overflow['ok'] and overflow['reason']=='recovery_history_full'
            assert not root_call(body)['created']
            result.update(normal_history_rows=64,recovery_history_rows=16,independent_capacity_verified=True)
        assert protect()==before
        assert Gate(root).read()['state'] in {'VERIFY_REQUIRED','RECOVERY_REQUIRED'}
        if parent.poll() is None:
            refused=call(config['socket'],{**normal_job,'request_id':'still-closed'});assert not refused['ok'] and refused.get('reason') in {'recovery_required','stale_gate_authority'}
        result.update(terminal=row['state'],storage_result=row.get('result'),protected_journal_and_tls_unchanged=True,updates_enabled=False,restored=False)
        return result,parent
    except Exception:
        if child and live(child):os.kill(child,signal.SIGKILL)
        if parent.poll() is None:parent.terminate()
        try:parent.wait(3)
        except subprocess.TimeoutExpired:parent.kill();parent.wait()
        raise

def main():
    from tools.storage_vm import scenario
    if os.geteuid()!=0:raise PermissionError('isolated VM root required')
    os.umask(0o077);source=hashes();out=P/'evidence/recovery-validation.json'
    if out.exists():
        archive=P/'evidence/recovery-attempts';archive.mkdir(exist_ok=True);shutil.copyfile(out,archive/(str(time.time_ns())+'.json'))
    def publish(report):
        text=json.dumps(report,indent=2);out.write_text(text);out.with_suffix('.html').write_text('<!doctype html><meta charset="utf-8"><pre>'+html.escape(text)+'</pre>')
    report={'passed':False,'status':'in_progress','cases':[],'scope':'formal source-run certweft.service + root recovery_executor; isolated Linux VM ext4 loop store; real Nginx fresh TLS observation','untested':['TLS restoration/unlock','persistent systemd deployment','VM reboot','power loss','physical media errors','D-state cleanup','automatic history/probe recycling']};publish(report)
    matrix=[('enospc','pre','success'),('enospc','post','restart'),('enospc','pre','probe-restart'),('enospc','pre','expired-restart'),('enospc','pre','expired-run'),('enospc','pre','expired-finish'),('enospc','pre','malformed-budget'),('enospc','pre','enospc'),('readonly','pre','readonly'),('enospc','pre','sqlite-full'),('enospc','pre','bad-schema'),('enospc','pre','target-drift'),('enospc','pre','unknown-probe'),('enospc','pre','history'),('sqlite_full','post','success-latched')]
    try:
        for kind,phase,mode in matrix:
            try:detail=scenario(kind,phase,check_gate=True,verification_mode=mode)
            except Exception as error:
                report['cases'].append({'mode':mode,'passed':False,'error':type(error).__name__+': '+str(error)});raise
            report['cases'].append(detail);publish(report)
        report['passed']=True;report['status']='completed'
    except Exception as error:traceback.print_exc();report['error']=type(error).__name__+': '+str(error);report['status']='failed'
    report['source_sha256']=source;report['source_unchanged']=source==hashes();report['passed']=report['passed'] and report['source_unchanged'];report['environment']={'python':sys.version.split()[0],'kernel':os.uname().release,'machine':os.uname().machine};publish(report)
    print(json.dumps({'passed':report['passed'],'cases':len(report['cases']),'error':report.get('error')}));return 0 if report['passed'] else 1
if __name__=='__main__':sys.exit(main())
