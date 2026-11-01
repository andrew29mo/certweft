"""Closed journal preparation through the actual root service in a Linux VM."""
import contextlib,errno,hashlib,html,json,os,pathlib,shutil,signal,sqlite3,subprocess,sys,time,traceback
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
from certweft import deadlines
from certweft.core import Writer,run,fingerprint
from certweft.gate import Gate
from certweft.reconciliation import snapshot,digest,receipt
from tools.executor_vm import request,hashes
P=pathlib.Path(__file__).resolve().parents[1]
MATRIX=['success','latched','terminal-history','expired-before','expired-after','expired-result','stale-before','stale-result','journal-drift','pointer-drift','invalid-certificate','sqlite-full','readonly','enospc','crash-before','crash-after','crash-result','success-restart']

def settings(work,mode):
    point='reconcile-main-commit' if mode in {'expired-before','stale-before','crash-before'} else 'reconcile-main-committed' if mode in {'expired-after','crash-after'} else 'reconcile-result-commit' if mode in {'expired-result','stale-result','crash-result'} else 'reconcile-start'
    return {'reconciliation_pause_at':point,'reconciliation_marker':str(work/'reconciliation.json'),'reconciliation_pause_once':True}

def exercise(root,work,config,parent,call,normal_job,certificate,mode):
    child=None;bound=False;filler=None;damaged=None;cfg=work/'reconciliation-config'
    def live(pid):
        try:return pathlib.Path('/proc',str(pid),'stat').read_text().split()[2]!='Z'
        except (FileNotFoundError,ProcessLookupError):return False
    def db():return contextlib.closing(sqlite3.connect('file:'+str(root/'journal.db')+'?mode=ro',uri=True,timeout=.2))
    def readmain():
        with db() as d:return snapshot(d),receipt(d)
    def rootcall(body):return request(config['socket'],body)
    def count():return len((work/'executors.jsonl').read_text().splitlines())
    def poll(identity):
        for _ in range(360):
            if parent.poll() is not None:return None
            try:
                r=rootcall({'op':'recovery-request-status','request_id':identity})
                if r['ok'] and r['result']['state'] not in {'ACCEPTED','RUNNING'} and not rootcall({'op':'recovery-status'})['executor_busy']:return r['result']
            except (OSError,ValueError,EOFError):
                # Transport loss is not success. Only an observed process exit
                # permits the caller's explicit fail-stop/restart assertions.
                try:parent.wait(timeout=1)
                except subprocess.TimeoutExpired:raise
                return None
            time.sleep(.025)
        raise AssertionError('preparation_stuck')
    def start():
        config.pop('reconciliation_pause_at',None);cfg.write_text(json.dumps(config));pathlib.Path(config['socket']).unlink(missing_ok=True)
        log=(work/('reconciliation-restart-'+str(time.time_ns())+'.log')).open('wb')
        proc=subprocess.Popen([sys.executable,'-m','certweft.service',str(cfg)],cwd=P,stdout=log,stderr=subprocess.STDOUT);log.close()
        for _ in range(120):
            if proc.poll() is not None:raise AssertionError('preparation_restart_failed')
            if pathlib.Path(config['socket']).exists():return proc
            time.sleep(.025)
        proc.kill();proc.wait();raise AssertionError('preparation_restart_endpoint')
    try:
        if mode=='terminal-history':
            with contextlib.closing(sqlite3.connect(root/'journal.db')) as d,d:
                for identity,status in [('historic-bad','DEGRADED'),('historic-good','COMMITTED')]:d.execute('INSERT INTO requests VALUES(?,?,?,?,NULL)',(identity,'b'*64,status,json.dumps({'fixture_history':True})))
        prior,prior_receipt=readmain();core=json.loads(prior['state'][0][1]);pointer=os.readlink(root/'active.conf')
        generations={str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for d in root.glob('v-*') for p in d.iterdir() if p.is_file()}
        gate=rootcall({'op':'recovery-status'})['gate'];assert gate['state']=='VERIFIED_CLOSED'
        body={'op':'reconcile-closed','request_id':'prepare-one','certificate_request_id':certificate['request_id'],'timeout_seconds':1 if mode.startswith('expired') else 10,**Gate.token(gate)}
        denied=call(config['socket'],body);assert not denied['ok'] and denied['reason']=='admin_required'
        accepted=rootcall(body);assert accepted['ok'] and accepted['created'];original=accepted['result']
        for _ in range(160):
            if (work/'reconciliation.json').exists():child=json.loads((work/'reconciliation.json').read_text())['pid'];break
            time.sleep(.02)
        else:raise AssertionError('preparation_checkpoint_missing')
        assert live(child)
        detail={'mode':mode,'formal_service':True,'root_only':True,'captured_snapshot':True}
        locked=mode in {'expired-before','stale-before','crash-before','expired-result','stale-result','crash-result'}
        if not locked:
            same=rootcall(body);assert not same['created'] and same['result']['timing']==original['timing']
            conflict=rootcall({**body,'timeout_seconds':9});assert not conflict['ok'] and conflict['reason']=='request_conflict'
            detail['inflight_dedup_and_conflict']=True
        if mode in {'journal-drift','sqlite-full'}:
            with contextlib.closing(sqlite3.connect(root/'journal.db')) as d,d:
                if mode=='journal-drift':d.execute("UPDATE requests SET state='CANCEL_REQUESTED' WHERE state='RUNNING'")
                else:
                    d.execute('CREATE TABLE reconciliation_pressure(data BLOB)')
                    # The service pager limit (set in the base fixture) makes this
                    # actual allocation fail with SQLITE_FULL at the reserved probe.
                    d.execute('CREATE TRIGGER reconciliation_full BEFORE UPDATE ON storage_probe BEGIN INSERT INTO reconciliation_pressure VALUES(zeroblob(1048576)); END')
        if mode=='pointer-drift':
            assert core['candidate'];tmp=root/'fixture-pointer';tmp.symlink_to('v-'+core['candidate']+'/tls.conf');os.replace(tmp,root/'active.conf')
        if mode=='invalid-certificate':
            # Root fault after admission: structural committed digest must detect drift.
            path=root/('v-'+core['committed'])/'cert.pem';damaged=(path,path.read_bytes());path.write_text('invalid fixture certificate')
        if mode=='readonly':
            run(['mount','--bind',root,root]);bound=True;run(['mount','-o','remount,bind,ro',root])
            try:(root/'readonly-probe').write_bytes(b'x')
            except OSError as e:assert e.errno==errno.EROFS;detail['observed_errno']=e.errno
            else:raise AssertionError('readonly_not_real')
        if mode=='enospc':
            filler=root/'reconciliation-filler'
            with filler.open('wb',buffering=0) as f:
                try:
                    while True:f.write(b'x'*4096)
                except OSError as e:assert e.errno==errno.ENOSPC;detail['observed_errno']=e.errno
            try:
                with (root/'reconciliation-full-probe').open('wb',buffering=0) as f:f.write(b'x'*4096);os.fsync(f.fileno())
            except OSError as e:assert e.errno==errno.ENOSPC
            else:raise AssertionError('full_not_real')
        if mode.startswith('stale'):
            newer=Gate(root).start();detail['newer_gate_preserved']=True
        if mode.startswith('expired'):
            left=(original['timing']['budget']['expires_boot_ns']-deadlines.now_ns())/1e9
            if left>0:time.sleep(left+.04)
        if mode.startswith('crash'):
            # Direct RO observations precede process termination, excluding stop cleanup.
            before_kill,record=readmain()
            with contextlib.closing(sqlite3.connect('file:'+str(root/'recovery.db')+'?mode=ro',uri=True)) as d:
                assert d.execute("SELECT state FROM recovery_requests WHERE id='prepare-one'").fetchone()[0]=='RUNNING'
            assert (record is not None)==(mode!='crash-before')
            os.kill(parent.pid,signal.SIGKILL);parent.wait(3)
            competing=subprocess.run([sys.executable,'-m','certweft.service',str(work/'certificate-config')],cwd=P,capture_output=True,timeout=3);assert competing.returncode==73
            os.kill(child,signal.SIGKILL)
            for _ in range(100):
                if not live(child):break
                time.sleep(.02)
            else:raise AssertionError('old_preparer_alive')
            before_count=count();parent=start();row=poll(body['request_id']);assert row['state'] in {'INTERRUPTED','EXPIRED'}
            assert row['timing']==original['timing'] and row['target']==original['target']
            assert not rootcall(body)['created'] and count()==before_count
            refused=rootcall({**body,'request_id':'stale-after-restart'});assert not refused['ok'] and refused['reason']=='stale_gate_authority'
            if mode=='crash-before':assert readmain()[0]==prior
            else:assert readmain()[0]==before_kill
            assert not rootcall({'op':'recovery-status'})['journal_prepared_closed']
            detail.update(pending_observed_before_kill=True,old_executor_fenced=True,restart_no_replay_or_budget_reset=True)
            if mode=='crash-after':
                g=rootcall({'op':'recovery-status'})['gate'];g=rootcall({'op':'prepare-recovery',**Gate.token(g)})['gate']
                restore={**Gate.token(g),'op':'recover-certificate','request_id':'explicit-new-certificate','timeout_seconds':10}
                assert rootcall(restore)['created'];fresh=poll(restore['request_id']);assert fresh['state']=='VERIFIED_CLOSED'
                newgate=rootcall({'op':'recovery-status'})['gate'];freshbody={**body,**Gate.token(newgate),'request_id':'explicit-new-preparation','certificate_request_id':fresh['request_id']}
                assert rootcall(freshbody)['created'];retry=poll(freshbody['request_id']);assert retry['state']=='JOURNAL_VERIFIED_CLOSED'
                detail['explicit_fresh_recovery_after_partial_commit']=True
        else:
            os.kill(child,signal.SIGCONT);row=poll(body['request_id'])
            if bound:run(['umount',root]);bound=False
            if filler:filler.unlink();filler=None
            if row is None:
                assert mode in {'readonly','enospc'} and parent.wait(3)==75
                parent=start();row=poll(body['request_id']);assert row['state'] in {'INTERRUPTED','FAILED','EXPIRED'}
                detail['result_unrecordable_failstop_then_closed_restart']=True
            expected='EXPIRED' if mode.startswith('expired') else 'FAILED' if mode.startswith('stale') or mode in {'journal-drift','pointer-drift','invalid-certificate','sqlite-full','readonly','enospc'} else 'JOURNAL_VERIFIED_CLOSED'
            if mode not in {'readonly','enospc'}:assert row['state']==expected,(mode,row)
            if mode=='sqlite-full':assert row['result']['sqlite_error']=='SQLITE_FULL'
            if mode=='journal-drift':assert row['result']['reason']=='journal_drift'
            if mode=='pointer-drift':assert row['result']['reason']=='committed_pointer_required'
            if mode=='invalid-certificate':assert row['result']['reason']=='committed_drift'
            if mode.startswith('stale'):assert Gate(root).read()==newer and row['result']['reason']=='stale_gate_authority'
            after,record=readmain()
            if mode in {'expired-before','stale-before','sqlite-full','readonly','enospc'}:assert after==prior and record is None
            if mode in {'expired-after','expired-result','stale-result'}:assert record is not None and after!=prior and not rootcall({'op':'recovery-status'})['journal_prepared_closed']
            before_count=count();same=rootcall(body);assert not same['created'] and same['result']==row and count()==before_count
            if expected=='JOURNAL_VERIFIED_CLOSED':
                assert record is not None and row['result']['receipt_digest']==digest(record) and row['result']['after_digest']==digest(after)
                assert json.loads(after['state'][0][1])['state']=='READY' and json.loads(after['state'][0][1])['candidate'] is None
                assert json.loads(after['state'][0][1])['epoch']!=core['epoch'] and after['health'][0][1:] == ('HEALTHY',None)
                prior_rows={r[0]:r for r in prior['requests']};after_rows={r[0]:r for r in after['requests']}
                for identity,previous in prior_rows.items():
                    if previous[2] in {'ACCEPTED','RUNNING','CANCEL_REQUESTED'}:
                        assert after_rows[identity][2]=='INTERRUPTED' and after_rows[identity][1]==previous[1] and after_rows[identity][4]==previous[4]
                    else:assert after_rows[identity]==previous
                current=rootcall({'op':'recovery-status'});assert current['journal_prepared_closed'] and not current['storage_health_not_verified'] and not current['gate_allows_updates']
                detail.update(main_receipt_and_root_proof_match=True,ready_healthy_but_closed=True,historical_terminal_rows_preserved=True)
                if mode=='latched':assert row['result']['prior_health']=='STORAGE_FAILED'
                if mode=='success-restart':
                    before_count=count();os.kill(parent.pid,signal.SIGKILL);parent.wait(3);parent=start()
                    current=rootcall({'op':'recovery-status'});assert current['gate']['state']=='RECOVERY_REQUIRED' and not current['journal_prepared_closed']
                    assert not rootcall(body)['created'] and count()==before_count and readmain()[0]==after
                    detail['completed_restart_still_closed']=True
        current_core=json.loads(readmain()[0]['state'][0][1])
        refused=call(config['socket'],{**normal_job,'request_id':'preparation-never-opens','epoch':current_core['epoch'],'revision':current_core['revision']})
        assert not refused['ok'] and not refused.get('created')
        assert refused.get('reason') in {'stale_gate_authority','recovery_required'},refused
        detail['normal_update_with_current_core_rejected_by_gate']=refused['reason']
        assert Gate(root).read()['state'] in {'VERIFIED_CLOSED','RECOVERY_REQUIRED'}
        if mode not in {'pointer-drift','invalid-certificate'}:
            assert os.readlink(root/'active.conf')==pointer
            assert {str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for d in root.glob('v-*') for p in d.iterdir() if p.is_file()}==generations
        detail.update(terminal=row['state'],terminal_result=row['result'],original_timing_preserved=row['timing']==original['timing'],updates_enabled=False)
        return detail,parent
    except Exception:
        if parent.poll() is None:
            parent.kill();parent.wait(3)
        raise
    finally:
        if bound:run(['umount',root])
        if filler:filler.unlink(missing_ok=True)
        if child and live(child):os.kill(child,signal.SIGKILL)
        if damaged:damaged[0].write_bytes(damaged[1]) # Restore only fixture corruption so nginx quit can parse its config.

def main():
    from tools.storage_vm import scenario
    if os.geteuid()!=0:raise PermissionError('isolated Linux VM root required')
    os.umask(0o077);source=hashes();out=P/'evidence/journal-preparation.json';archive=P/'evidence/preparation-attempts';archive.mkdir(exist_ok=True)
    if out.exists():shutil.copyfile(out,archive/(str(time.time_ns())+'.json'))
    def publish(r):
        text=json.dumps(r,indent=2);out.write_text(text);out.with_suffix('.html').write_text('<!doctype html><meta charset="utf-8"><pre>'+html.escape(text)+'</pre>')
    report={'passed':False,'status':'in_progress','cases':[],'scope':'formal source-run root service + lease-fenced executor, actual journal, Nginx and fresh TLS in isolated Linux VM','untested':['admission reopening','normal DEGRADED admission policy change','installed systemd lifecycle','VM reboot','power loss','general COMMIT I/O/fsync failures','physical media','zero downtime']};publish(report)
    try:
        for mode in MATRIX:
            try:detail=scenario('sqlite_full' if mode in {'latched','sqlite-full'} else 'enospc','post',check_gate=True,certificate_mode='reconcile-'+mode)
            except Exception as e:report['cases'].append({'mode':mode,'passed':False,'error':type(e).__name__+': '+str(e)});raise
            report['cases'].append(detail);publish(report)
        report.update(passed=True,status='completed')
    except Exception as e:traceback.print_exc();report.update(error=type(e).__name__+': '+str(e),status='failed')
    report.update(source_sha256=source,source_unchanged=source==hashes(),environment={'python':sys.version.split()[0],'kernel':os.uname().release,'machine':os.uname().machine});report['passed']=report['passed'] and report['source_unchanged'];publish(report)
    print(json.dumps({'passed':report['passed'],'cases':len(report['cases']),'error':report.get('error')}));return 0 if report['passed'] else 1
if __name__=='__main__':sys.exit(main())
