"""Formal closed opening intentions; actual services, SQLite and isolated VM."""
import contextlib,html,json,os,pathlib,shutil,signal,sqlite3,subprocess,sys,time,traceback,uuid
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
from certweft import deadlines
from certweft.core import Writer
from certweft.gate import Gate
from certweft.reconciliation import receipt,snapshot,digest
from certweft.opening import marker
from tools.executor_vm import hashes,request
P=pathlib.Path(__file__).resolve().parents[1]
MATRIX=['success','degraded-added','degraded-changed','receipt-missing','receipt-mismatch','core-drift','incomplete-preparation','expired-before','expired-after','expired-result','expired-ready','readiness-expiry','crash-before','crash-after','crash-result','stale-before','stale-result','newer-marker','malformed-marker','completed-restart']

def settings(work,mode):
    point='opening-main-commit' if mode in {'expired-before','crash-before','stale-before'} else 'opening-main-committed' if mode in {'expired-after','crash-after','newer-marker'} else 'opening-result-commit' if mode in {'expired-result','crash-result','stale-result'} else 'opening-start'
    result={'opening_pause_at':point,'opening_marker':str(work/'opening.json'),'opening_pause_once':True}
    if mode=='readiness-expiry':result['opening_readiness_expiry_marker']=str(work/'readiness-expiry.json')
    return result

def exercise(root,work,config,parent,call,normal_job,prepared,mode,source_seconds=None):
    child=None;cfg=work/'opening-config';crossing_responses=[]
    def db():return contextlib.closing(sqlite3.connect('file:'+str(root/'journal.db')+'?mode=ro',uri=True,timeout=.2))
    def state():
        with db() as d:return snapshot(d)
    def rootcall(body):return request(config['socket'],body)
    def inventory():return len((work/'executors.jsonl').read_text().splitlines())
    def live(pid):
        try:return pathlib.Path('/proc',str(pid),'stat').read_text().split()[2]!='Z'
        except (FileNotFoundError,ProcessLookupError):return False
    def poll(identity):
        for _ in range(360):
            if parent.poll() is not None:raise AssertionError('opening_service_exited')
            row=rootcall({'op':'recovery-request-status','request_id':identity})['result']
            if row['state'] not in {'ACCEPTED','RUNNING'}:
                existed=(work/'readiness-expiry.json').exists()
                status=rootcall({'op':'recovery-status'})
                if mode=='readiness-expiry' and not existed and (work/'readiness-expiry.json').exists():crossing_responses.append(status)
                if not status['executor_busy']:return row
            time.sleep(.025)
        raise AssertionError('opening_operation_stuck')
    def start():
        config.pop('opening_pause_at',None);cfg.write_text(json.dumps(config));pathlib.Path(config['socket']).unlink(missing_ok=True)
        log=(work/('opening-restart-'+str(time.time_ns())+'.log')).open('wb')
        proc=subprocess.Popen([sys.executable,'-m','certweft.service',str(cfg)],cwd=P,stdout=log,stderr=subprocess.STDOUT);log.close()
        for _ in range(120):
            if proc.poll() is not None:raise AssertionError('opening_restart_failed')
            try:
                ready=request(config['socket'],{'op':'recovery-status'});assert ready.get('ok'),ready
                proc.fixture_gate_authority=Gate.token(ready['gate']);return proc
            except (OSError,EOFError):time.sleep(.025)
        proc.kill();proc.wait();raise AssertionError('opening_restart_endpoint')
    def probe_executor(authority,core,recover_request=False):
        # A root-controlled adversarial direct invocation of the real executor.
        # This is not a test that a separate process acquired the service lease.
        frozen={**config,'gate_authority':authority};fd=os.open(config['lease'],os.O_RDONLY)
        try:
            body={'op':'recover-request','request_id':normal_job['request_id']} if recover_request else {'op':'activate','certificate':normal_job['certificate'],'epoch':core['epoch'],'revision':core['revision']}
            proc=subprocess.run([sys.executable,'-m','certweft.executor',str(fd)],pass_fds=(fd,),input=json.dumps({'peer_uid':0,'body':body,'config':frozen}).encode(),capture_output=True,cwd=P,timeout=5)
            assert proc.returncode==0;reply=json.loads(proc.stdout);assert not reply['ok'];return reply
        finally:os.close(fd)
    try:
        before=state();core=json.loads(before['state'][0][1]);old_gate=Gate(root).read()
        assert old_gate['state']=='VERIFIED_CLOSED' and core['state']=='READY'
        assert [r for r in before['requests'] if r[2]=='DEGRADED'],'real fault must leave referenced DEGRADED history'
        with db() as d:saved_receipt=receipt(d)
        pointer=os.readlink(root/'active.conf');versions={str(p.relative_to(root)):digest(p.read_bytes().hex()) for v in root.glob('v-*') for p in v.iterdir() if p.is_file()}
        body={'op':'prepare-opening','request_id':'opening-one','preparation_request_id':prepared['request_id'],'receipt_digest':digest(saved_receipt),'core_epoch':core['epoch'],'core_revision':core['revision'],'timeout_seconds':source_seconds if source_seconds is not None else 1 if mode.startswith('expired') or mode=='readiness-expiry' else 10,**Gate.token(old_gate)}
        denied=call(config['socket'],body);assert not denied['ok'] and denied['reason']=='admin_required'
        for change in [{'receipt_digest':'0'*64},{'core_revision':core['revision']+1}]:
            bad=rootcall({**body,**change,'request_id':'invalid-binding'});assert not bad['ok'] and bad['reason'] in {'preparation_binding_mismatch','core_pair_mismatch'}
        accepted=rootcall(body);assert accepted['ok'] and accepted['created'];original=accepted['result']
        for _ in range(160):
            if (work/'opening.json').exists():child=json.loads((work/'opening.json').read_text())['pid'];break
            time.sleep(.02)
        else:raise AssertionError('opening_checkpoint_missing')
        assert live(child)
        detail={'mode':mode,'root_only':True,'formal_service':True,'invalid_bindings_rejected':True}
        locked=mode in {'expired-before','crash-before','stale-before','expired-result','crash-result','stale-result'}
        if not locked:
            duplicate=rootcall(body);assert not duplicate['created'] and duplicate['result']['timing']==original['timing']
            bad=rootcall({**body,'core_revision':core['revision']+1});assert not bad['ok'] and bad['reason']=='request_conflict'
            detail['inflight_dedup_and_conflict']=True
        if mode in {'degraded-added','degraded-changed','receipt-missing','receipt-mismatch','core-drift','malformed-marker'}:
            with contextlib.closing(sqlite3.connect(root/'journal.db')) as d,d:
                if mode=='degraded-added':d.execute("INSERT INTO requests VALUES('unreferenced',?,'DEGRADED',NULL,NULL)",('a'*64,))
                elif mode=='degraded-changed':d.execute("UPDATE requests SET result='{}' WHERE state='DEGRADED'")
                elif mode=='receipt-missing':d.execute('DROP TABLE closed_reconciliation')
                elif mode=='receipt-mismatch':
                    changed=dict(saved_receipt,request_digest='0'*64);d.execute('UPDATE closed_reconciliation SET record=?',(json.dumps(changed),))
                elif mode=='core-drift':
                    changed=dict(core,epoch=uuid.uuid4().hex);d.execute('UPDATE state SET data=?',(json.dumps(changed),))
                else:d.execute('CREATE TABLE opening_intent(id INTEGER PRIMARY KEY,record TEXT)');d.execute("INSERT INTO opening_intent VALUES(1,'{}')")
        if mode=='incomplete-preparation':
            with contextlib.closing(sqlite3.connect(root/'recovery.db')) as d,d:d.execute("UPDATE recovery_requests SET state='FAILED' WHERE id=?",(prepared['request_id'],))
        if mode=='newer-marker':
            with contextlib.closing(sqlite3.connect(root/'journal.db')) as d,d:
                newer=marker(d);newer['request_id']='newer-intent';d.execute('UPDATE opening_intent SET record=?',(json.dumps(newer),))
        expected_main=state()
        if mode.startswith('stale'):new_gate=Gate(root).start()
        if mode.startswith('expired') and mode!='expired-ready':
            left=(original['timing']['budget']['expires_boot_ns']-deadlines.now_ns())/1e9
            if left>0:time.sleep(left+.04)
        if mode.startswith('crash'):
            with db() as d:committed_marker=marker(d)
            with contextlib.closing(sqlite3.connect('file:'+str(root/'recovery.db')+'?mode=ro',uri=True)) as d:assert d.execute("SELECT state FROM recovery_requests WHERE id='opening-one'").fetchone()[0]=='RUNNING'
            assert (committed_marker is not None)==(mode!='crash-before')
            os.kill(parent.pid,signal.SIGKILL);parent.wait(3)
            competing=subprocess.run([sys.executable,'-m','certweft.service',str(work/'certificate-config')],cwd=P,capture_output=True,timeout=3);assert competing.returncode==73
            os.kill(child,signal.SIGKILL)
            for _ in range(100):
                if not live(child):break
                time.sleep(.02)
            else:raise AssertionError('old_opening_executor_alive')
            count=inventory();parent=start();out=poll(body['request_id']);assert out['state'] in {'INTERRUPTED','EXPIRED'}
            assert not rootcall(body)['created'] and inventory()==count
            stale=rootcall({**body,'request_id':'old-intent'});assert not stale['ok'] and stale['reason']=='stale_gate_authority'
            assert not rootcall({'op':'recovery-status'})['opening_intent_verified_closed']
            detail.update(pending_observed_before_kill=True,old_executor_fences_takeover=True,restart_no_replay=True)
        else:
            os.kill(child,signal.SIGCONT);out=poll(body['request_id'])
            expected='EXPIRED' if mode in {'expired-before','expired-after','expired-result'} else 'FAILED' if mode.startswith('stale') or mode in {'degraded-added','degraded-changed','receipt-missing','receipt-mismatch','core-drift','incomplete-preparation','newer-marker','malformed-marker'} else 'OPENING_VERIFIED_CLOSED'
            assert out['state']==expected,(mode,out)
            reasons={'degraded-added':'unreferenced_degraded_history','degraded-changed':'preparation_journal_drift','receipt-missing':'preparation_receipt_required','receipt-mismatch':'preparation_binding_mismatch','core-drift':'core_pair_mismatch','incomplete-preparation':'completed_preparation_required','newer-marker':'stale_opening_marker','malformed-marker':'opening_marker_schema','stale-before':'stale_gate_authority','stale-result':'stale_gate_authority'}
            if mode in reasons:assert out['result']['reason']==reasons[mode],out
            count=inventory();assert rootcall(body)['result']==out and not rootcall(body)['created'] and inventory()==count
            current=rootcall({'op':'recovery-status'})
            assert current['opening_intent_verified_closed']==(expected=='OPENING_VERIFIED_CLOSED' and mode!='readiness-expiry')
            if expected=='OPENING_VERIFIED_CLOSED':
                with db() as d:stored=marker(d)
                assert out['result']['marker_digest']==digest(stored) and out['result']['degraded_reference_count']>=1
                assert out['target']['degraded_references']=={r[0]:digest(r) for r in before['requests'] if r[2]=='DEGRADED'}
                assert out['result']['release_authorized'] is False and out['result']['updates_enabled'] is False
                detail['exact_degraded_rows_referenced_without_rewrite']=True
                if mode=='readiness-expiry':
                    observed=json.loads((work/'readiness-expiry.json').read_text())
                    assert observed=={'point':'after-pair-validation','expiry_crossed':True}
                    assert len(crossing_responses)==1
                    assert crossing_responses[0]['opening_intent_verified_closed'] is False,'expired_readiness_response'
                    detail['crossing_status_response_readiness']=crossing_responses[0]['opening_intent_verified_closed']
                    assert deadlines.now_ns()>out['timing']['budget']['expires_boot_ns']
                    assert rootcall(body)['result']==out and not rootcall(body)['created']
                    detail['readiness_crossed_original_expiry_rejected']=True
                if mode=='expired-ready':
                    left=(out['timing']['budget']['expires_boot_ns']-deadlines.now_ns())/1e9
                    if left>0:time.sleep(left+.04)
                    assert not rootcall({'op':'recovery-status'})['opening_intent_verified_closed'] and rootcall(body)['result']==out
                    detail['completed_intent_expires_without_replay']=True
                if mode=='completed-restart':
                    count=inventory();os.kill(parent.pid,signal.SIGKILL);parent.wait(3);parent=start()
                    assert not rootcall({'op':'recovery-status'})['opening_intent_verified_closed'] and rootcall(body)['result']==out and inventory()==count
                    detail['historical_success_never_reopens_after_restart']=True
            if mode=='newer-marker':
                with db() as d:assert marker(d)==newer
            if mode=='malformed-marker':
                with db() as d:assert d.execute('SELECT record FROM opening_intent').fetchone()[0]=='{}'
            if mode.startswith('stale'):assert Gate(root).read()==new_gate
        assert out['timing']==original['timing'] and out['target']==original['target'] and state()==expected_main
        assert os.readlink(root/'active.conf')==pointer and {str(p.relative_to(root)):digest(p.read_bytes().hex()) for v in root.glob('v-*') for p in v.iterdir() if p.is_file()}==versions
        core_now=json.loads(state()['state'][0][1]);normal={**normal_job,'epoch':core_now['epoch'],'revision':core_now['revision'],'request_id':'opening-never-admits'}
        rejected=call(config['socket'],normal);assert not rejected['ok'] and rejected['reason'] in {'stale_gate_authority','recovery_required'}
        direct=probe_executor(Gate.token(Gate(root).read()),core_now);assert direct['reason']=='recovery_required'
        legacy=probe_executor(Gate.token(Gate(root).read()),core_now,True);assert legacy['reason']=='use_prepare_recovery'
        # Fault injection, not a supported transition: put the *service's own*
        # session token into a RUNNING marker. The shared pairing guard must deny.
        original_gate=Gate(root).read();session=parent.fixture_gate_authority
        forged={**original_gate,'epoch':session['gate_epoch'],'revision':session['gate_revision'],'state':'RUNNING','reason':'session_started'}
        try:
            Gate(root).write(forged)
            reject=call(config['socket'],{**normal,'request_id':'forged-running-submit'});assert not reject['ok'] and reject['reason']=='opening_handoff_required',reject
            direct=probe_executor(Gate.token(forged),core_now);assert direct['reason']=='opening_handoff_required',direct
            from certweft.operations import Operations
            with contextlib.closing(sqlite3.connect(root/'journal.db')) as d:
                try:Operations.commit(d,'missing',{},gate_authority=Gate.token(forged))
                except Exception as e:assert str(e)=='opening_handoff_required'
                else:raise AssertionError('unpaired_commit_allowed')
        finally:Gate(root).write(original_gate)
        assert state()==expected_main and not rootcall({'op':'recovery-status'})['gate_allows_updates']
        detail.update(terminal=out['state'],terminal_result=out['result'],original_budget_preserved=True,main_history_and_health_unchanged=True,gate_unchanged_except_explicit_fixture=True,entry_executor_commit_reject_unpaired_running=True,updates_enabled=False)
        return detail,parent
    except Exception:
        if parent.poll() is None:parent.kill();parent.wait(3)
        raise
    finally:
        if child and live(child):os.kill(child,signal.SIGKILL)

def main():
    from tools.storage_vm import scenario
    if os.geteuid()!=0:raise PermissionError('isolated Linux VM root required')
    os.umask(0o077);source=hashes();out=P/'evidence/opening-intent.json';archive=P/'evidence/opening-attempts';archive.mkdir(exist_ok=True)
    if out.exists():shutil.copyfile(out,archive/(str(time.time_ns())+'.json'))
    def publish(r):
        text=json.dumps(r,indent=2);out.write_text(text);out.with_suffix('.html').write_text('<!doctype html><meta charset="utf-8"><pre>'+html.escape(text)+'</pre>')
    report={'passed':False,'status':'in_progress','cases':[],'scope':'formal root service and inherited executor, actual journal + closed opening intentions in isolated Linux VM','untested':['actual reopening','fresh TLS/storage qualification inside opening intention','installed systemd lifecycle','VM reboot','power loss','opening-phase ENOSPC/EROFS/FULL and general COMMIT I/O/fsync faults','physical media','zero downtime']};publish(report)
    try:
        for mode in MATRIX:
            try:detail=scenario('sqlite_full','post',check_gate=True,certificate_mode='opening-'+mode)
            except Exception as e:report['cases'].append({'mode':mode,'passed':False,'error':type(e).__name__+': '+str(e)});raise
            report['cases'].append(detail);publish(report)
        from tools.opening_mutation import check_readiness_mutation
        report['readiness_mutation']=check_readiness_mutation()
        assert report['readiness_mutation']['passed'] and report['readiness_mutation']['cleanup_verified']
        report.update(passed=True,status='completed')
    except Exception as e:traceback.print_exc();report.update(error=type(e).__name__+': '+str(e),status='failed')
    report.update(source_sha256=source,source_unchanged=source==hashes(),environment={'python':sys.version.split()[0],'kernel':os.uname().release,'machine':os.uname().machine});report['passed']=report['passed'] and report['source_unchanged'];publish(report)
    print(json.dumps({'passed':report['passed'],'cases':len(report['cases']),'error':report.get('error')}));return 0 if report['passed'] else 1
if __name__=='__main__':sys.exit(main())
