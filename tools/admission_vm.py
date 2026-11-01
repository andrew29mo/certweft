"""Formal root reopening, crash boundaries and real post-recovery updates."""
import contextlib,errno,html,json,os,pathlib,shutil,signal,sqlite3,ssl,socket,subprocess,sys,time,traceback
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
from certweft import deadlines
from certweft.core import run,fingerprint
from certweft.gate import Gate
from certweft.admission import record
from certweft.reconciliation import digest
from tools.executor_vm import P,hashes,request
MATRIX=['success','reply-lost','restart-completed','expired-own','expired-source','expired-release','expired-completed','crash-main','crash-gate','crash-result','crash-completed','stale-main','stale-gate','stale-result','newer-record','degraded-changed','wrong-leaf','bad-http','enospc-before','readonly-before','readonly-stopped','sqlite-full-before','sqlite-full-main','sqlite-full-result','enospc-after','readonly-after']
def settings(work,mode):
    point='admission-main-committed' if mode in {'crash-main','stale-main','expired-release'} else 'admission-gate-write' if mode=='stale-gate' else 'admission-gate-published' if mode in {'crash-gate','newer-record','enospc-after','readonly-after'} else 'admission-result-commit' if mode in {'crash-result','stale-result','expired-own','expired-source'} else 'admission-result-committed' if mode in {'crash-completed','expired-completed'} else 'admission-confirmed' if mode=='sqlite-full-main' else 'admission-start'
    return {'admission_pause_at':point,'admission_marker':str(work/'admission.json'),'admission_pause_once':True}

def exercise(root,work,config,parent,call,normal_job,released,mode):
    child=None;bound=False;filler=None;restore=[];cfg=work/'admission-config';start_time=time.monotonic()
    def db(path=None):return contextlib.closing(sqlite3.connect('file:'+str(path or root/'journal.db')+'?mode=ro',uri=True,timeout=.2))
    def rootcall(body):return request(config['socket'],body)
    def inventory():return len((work/'executors.jsonl').read_text().splitlines())
    def live(pid):
        try:return pathlib.Path('/proc',str(pid),'stat').read_text().split()[2]!='Z'
        except FileNotFoundError:return False
    def memory(pid):return {l.split(':')[0]:l.split(':')[1].strip() for l in pathlib.Path('/proc',str(pid),'status').read_text().splitlines() if l.startswith(('VmRSS:','VmHWM:'))}
    def poll(identity):
        for _ in range(480):
            if parent.poll() is not None:return None
            try:
                r=rootcall({'op':'recovery-request-status','request_id':identity})['result']
                if r['state'] not in {'ACCEPTED','RUNNING'} and not rootcall({'op':'recovery-status'})['executor_busy']:return r
            except (OSError,ValueError,EOFError):parent.wait(4);return None
            time.sleep(.025)
        raise AssertionError('admission_stuck')
    def restart():
        config.pop('admission_pause_at',None);cfg.write_text(json.dumps(config));pathlib.Path(config['socket']).unlink(missing_ok=True)
        log=(work/('admission-restart-'+str(time.time_ns())+'.log')).open('wb');p=subprocess.Popen([sys.executable,'-m','certweft.service',str(cfg)],cwd=P,stdout=log,stderr=subprocess.STDOUT);log.close()
        for _ in range(120):
            if p.poll() is not None:raise AssertionError('admission_restart_failed')
            try:
                ready=rootcall({'op':'recovery-status'});assert ready['ok'];p.fixture_gate_authority=Gate.token(ready['gate']);return p
            except OSError:time.sleep(.025)
        p.kill();p.wait();raise AssertionError('admission_restart_timeout')
    def expire(b):
        left=(b['expires_boot_ns']-deadlines.now_ns())/1e9
        if left>0:time.sleep(left+.025)
    def repair():
        nonlocal bound,filler
        if bound:run(['umount',root]);bound=False
        if filler:filler.unlink();filler=None
        if mode=='sqlite-full-result':
            with contextlib.closing(sqlite3.connect(root/'recovery.db')) as d,d:d.execute('DROP TRIGGER IF EXISTS admission_full');d.execute('DROP TABLE IF EXISTS admission_pressure')
    def assert_denied():
        assert not rootcall({'op':'recovery-status'})['gate_allows_updates']
        # Request a real, syntactically valid new activation, not a malformed probe.
        with db() as d:core=json.loads(d.execute('SELECT data FROM state').fetchone()[0])
        bad=call(config['socket'],{**normal_job,'request_id':'must-stay-closed','epoch':core['epoch'],'revision':core['revision']})
        assert not bad['ok'] and bad['reason'] in {'recovery_required','stale_gate_authority','opening_handoff_required'},bad
    def observe():
        ctx=ssl.create_default_context(cafile=config['writer']['ca'])
        with socket.create_connection((config['writer']['ip'],config['writer']['port']),2) as raw:
            with ctx.wrap_socket(raw,server_hostname='localhost') as s:
                assert not s.session_reused;fp=__import__('hashlib').sha256(s.getpeercert(True)).hexdigest();s.sendall(b'GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n');return fp,s.recv(4096).split(b'\r\n')[0]
    try:
        with db() as d:
            old_degraded=d.execute("SELECT * FROM requests WHERE state='DEGRADED' ORDER BY id").fetchall();core=json.loads(d.execute('SELECT data FROM state').fetchone()[0])
        body={'op':'open-updates','request_id':'open-one','release_request_id':released['request_id'],'release_receipt_digest':released['result']['receipt_digest'],'timeout_seconds':1 if mode in {'expired-own','expired-completed'} else 10,**Gate.token(Gate(root).read())}
        # Admission source uses the real three-second release only for its expiry
        # case; all other source intents retain the configured ten seconds.
        denied=call(config['socket'],body);assert not denied['ok'] and denied['reason']=='admin_required'
        if mode=='reply-lost':
            with socket.socket(socket.AF_UNIX) as lost:lost.connect(config['socket']);lost.sendall(json.dumps(body).encode()+b'\n')
            accepted=rootcall(body);assert accepted['ok'] and not accepted['created'],accepted
        else:
            accepted=rootcall(body);assert accepted['ok'] and accepted['created'],accepted
        original=accepted['result'];detail={'mode':mode,'formal_service':True,'service_memory_before':memory(parent.pid)}
        for _ in range(200):
            if (work/'admission.json').exists():child=json.loads((work/'admission.json').read_text())['pid'];break
            time.sleep(.02)
        else:raise AssertionError('admission_checkpoint_missing')
        detail['executor_memory_at_checkpoint']=memory(child)
        if mode not in {'crash-gate','crash-result','stale-result','expired-own','expired-source','newer-record','enospc-after','readonly-after','stale-gate'}:
            same=rootcall(body);assert not same['created'] and same['result']['timing']==original['timing'] and same['result']['target']==original['target']
            bad=rootcall({**body,'timeout_seconds':9});assert not bad['ok'] and bad['reason']=='request_conflict'
        # Directly verify intermediate evidence without trying the blocked SQL
        # endpoint while its decision barrier is intentionally SIGSTOPed.
        if mode in {'crash-main','crash-gate','crash-result','newer-record','enospc-after','readonly-after'}:
            with db() as d:assert record(d) is not None
            with db(root/'recovery.db') as d:assert d.execute("SELECT state FROM recovery_requests WHERE id='open-one'").fetchone()[0]=='RUNNING'
            from certweft.opening import require_updates
            try:require_updates(root,Gate.token(Gate(root).read()))
            except __import__('certweft.core',fromlist=['Rejected']).Rejected:pass
            else:raise AssertionError('partial_pair_admitted')
            detail['incomplete_pair_not_permission']=True
        if mode=='newer-record':
            with contextlib.closing(sqlite3.connect(root/'journal.db')) as d,d:
                newer=record(d);newer['request_id']='newer';d.execute('UPDATE admission_release SET record=?',(json.dumps(newer),))
        if mode=='degraded-changed':
            with contextlib.closing(sqlite3.connect(root/'journal.db')) as d,d:d.execute("UPDATE requests SET result='{}' WHERE state='DEGRADED'")
        if mode in {'sqlite-full-before','sqlite-full-main'}:
            with contextlib.closing(sqlite3.connect(root/'journal.db')) as d,d:
                d.execute('CREATE TABLE admission_pressure(data BLOB)')
                if mode=='sqlite-full-main':d.execute('CREATE TABLE admission_release(id INTEGER PRIMARY KEY,record TEXT)');d.execute("INSERT INTO admission_release VALUES(1,?)",(json.dumps(__import__('certweft.admission',fromlist=['expected']).expected(original)),))
                target='BEFORE UPDATE ON storage_probe' if mode.endswith('before') else 'BEFORE INSERT ON admission_release'
                d.execute('CREATE TRIGGER admission_full '+target+' BEGIN INSERT INTO admission_pressure VALUES(zeroblob(1048576)); END')
        if mode=='sqlite-full-result':
            with contextlib.closing(sqlite3.connect(root/'recovery.db')) as d,d:d.execute('CREATE TABLE admission_pressure(data BLOB)');d.execute("CREATE TRIGGER admission_full BEFORE UPDATE ON recovery_requests WHEN NEW.state='OPENED' BEGIN INSERT INTO admission_pressure VALUES(zeroblob(1048576)); END")
        if mode.startswith('enospc'):
            filler=root/'admission-filler'
            with filler.open('wb',buffering=0) as f:
                try:
                    while True:f.write(b'x'*4096)
                except OSError as e:assert e.errno==errno.ENOSPC;detail['observed_errno']=e.errno
            try:
                with (root/'admission-full-probe').open('wb',buffering=0) as f:f.write(b'x'*4096);os.fsync(f.fileno())
            except OSError as e:assert e.errno==errno.ENOSPC
            else:raise AssertionError('enospc_not_real')
        if mode.startswith('readonly'):
            run(['mount','--bind',root,root]);bound=True;run(['mount','-o','remount,bind,ro',root])
            try:(root/'admission-ro-probe').write_bytes(b'x')
            except OSError as e:assert e.errno==errno.EROFS;detail['observed_errno']=e.errno
            else:raise AssertionError('readonly_not_real')
        if mode=='wrong-leaf':
            other=next(v for v in root.glob('v-*') if v.name!='v-'+core['committed']);pointer=os.readlink(root/'active.conf');tmp=root/'fixture-select';tmp.symlink_to(other.name+'/tls.conf');os.replace(tmp,root/'active.conf');run(['/usr/sbin/nginx','-s','reload','-c',config['writer']['conf']])
            for _ in range(100):
                if observe()[0]!=fingerprint(root/('v-'+core['committed'])/'cert.pem'):break
                time.sleep(.02)
            else:raise AssertionError('wrong_leaf_not_live')
            tmp.symlink_to(pointer);os.replace(tmp,root/'active.conf')
        if mode=='bad-http':
            conf=pathlib.Path(config['writer']['conf']);restore.append((conf,conf.read_bytes()));conf.write_text(conf.read_text().replace('return 200 "ok"','return 503 "bad"'));run(['/usr/sbin/nginx','-s','reload','-c',conf])
            for _ in range(100):
                if observe()[1].startswith(b'HTTP/1.1 503'):break
                time.sleep(.02)
            else:raise AssertionError('bad_http_not_live')
        if mode in {'expired-own','expired-completed'}:expire(original['timing']['budget'])
        if mode=='expired-source':expire(original['target']['release_target']['source_budget'])
        if mode=='expired-release':expire(original['target']['release_budget'])
        if mode.startswith('stale'):new_gate=Gate(root).start()
        if mode=='readonly-stopped':
            # Keep the known executor stopped: repair must never make it live
            # again after its coordinator has failed. A real catalog request on
            # the read-only store forces the formal fault-latch/failstop path.
            try:rootcall({'op':'recovery-request-status','request_id':'open-one'})
            except (EOFError,OSError):pass
            assert parent.wait(3)==75
            assert not live(child),'fatal_exit_left_stopped_executor'
            repair();parent=restart();out=poll('open-one');assert out['state'] in {'INTERRUPTED','EXPIRED'}
            assert_denied();detail.update(stopped_executor_reaped_before_repair=True,unrecordable_fault_failstop=True)
        elif mode.startswith('crash'):
            with db(root/'recovery.db') as d:assert d.execute("SELECT state FROM recovery_requests WHERE id='open-one'").fetchone()[0]==('OPENED' if mode=='crash-completed' else 'RUNNING')
            os.kill(parent.pid,signal.SIGKILL);parent.wait(3)
            competing=subprocess.run([sys.executable,'-m','certweft.service',str(work/'certificate-config')],cwd=P,capture_output=True,timeout=3);assert competing.returncode==73
            os.kill(child,signal.SIGKILL)
            for _ in range(100):
                if not live(child):break
                time.sleep(.02)
            else:raise AssertionError('old_executor_alive')
            count=inventory();parent=restart();out=poll('open-one');assert inventory()==count and out['state'] in ({'OPENED'} if mode=='crash-completed' else {'INTERRUPTED','EXPIRED'})
            assert_denied();detail.update(pending_or_terminal_observed_before_kill=True,old_executor_fences_takeover=True,restart_never_replays=True)
        else:
            os.kill(child,signal.SIGCONT);out=poll('open-one')
            # Kill first when the process cannot report; only then repair fixture.
            if out is None:
                assert mode.startswith(('enospc','readonly')) and parent.wait(3)==75
                assert not live(child),'fatal_exit_left_live_executor'
                detail['active_executor_reaped_before_repair']=True
                repair();parent=restart();out=poll('open-one');assert out['state'] in {'INTERRUPTED','EXPIRED','FAILED'};detail['unrecordable_fault_failstop']=True
            else:repair()
            success=mode in {'success','reply-lost','restart-completed'}
            if success:
                assert out['state']=='OPENED',out
                assert rootcall({'op':'recovery-status'})['gate_allows_updates']
                # A historical replay never executes again, including lost reply.
                count=inventory();same=rootcall(body);assert not same['created'] and same['result']==out and inventory()==count
                if mode=='reply-lost':
                    with socket.socket(socket.AF_UNIX) as s:s.connect(config['socket']);s.sendall(json.dumps(body).encode()+b'\n')
                    same=rootcall(body);assert not same['created'] and same['result']==out and inventory()==count
                with db() as d:now=json.loads(d.execute('SELECT data FROM state').fetchone()[0]);assert d.execute("SELECT * FROM requests WHERE state='DEGRADED' ORDER BY id").fetchall()==old_degraded
                job={**normal_job,'request_id':'after-reopen','epoch':now['epoch'],'revision':now['revision']}
                expected=fingerprint(work/'new.pem');assert observe()[0]!=expected
                began=call(config['socket'],job);assert began['ok'] and began['created'],began
                for _ in range(300):
                    updated=call(config['socket'],{'op':'request-status','request_id':job['request_id']})['result']
                    if updated['state'] not in {'ACCEPTED','RUNNING','CANCEL_REQUESTED'} and not rootcall({'op':'recovery-status'})['executor_busy']:break
                    time.sleep(.025)
                assert updated['state']=='COMMITTED',updated
                assert observe()==(expected,b'HTTP/1.1 200 OK')
                with db() as d:assert d.execute("SELECT * FROM requests WHERE state='DEGRADED' ORDER BY id").fetchall()==old_degraded
                stale=rootcall({**body,'request_id':'stale-open'});assert not stale['ok'] and stale['reason']=='stale_gate_authority'
                detail.update(real_update_committed=True,new_leaf_observed_over_fresh_tls=True,terminal_degraded_history_unchanged=True)
                if mode=='restart-completed':
                    parent.terminate();parent.wait(3);count=inventory();parent=restart();assert inventory()==count;assert_denied();detail['normal_stop_restart_requires_recovery_again']=True
            elif mode=='expired-completed':
                assert out['state']=='OPENED';assert_denied();detail['historical_root_commit_not_current_permission']=True
            else:
                assert out['state'] in ({'EXPIRED'} if mode.startswith('expired') else {'FAILED','INTERRUPTED','EXPIRED'}),out
                assert_denied()
                if mode.startswith('sqlite-full'):assert out['result']['sqlite_error']=='SQLITE_FULL',out
                if mode in {'wrong-leaf','bad-http'}:assert out['result']['failure_stage']=='tls_confirmation' and out['result']['reason']=='confirmation_timeout',out
                if mode.startswith('stale'):assert Gate(root).read()==new_gate
                if mode=='newer-record':
                    with db() as d:assert record(d)==newer
        assert out['timing']==original['timing'] and out['target']==original['target']
        count=inventory();same=rootcall(body);assert not same['created'] and same['result']==out and inventory()==count
        with db(root/'recovery.db') as d:assert json.loads(d.execute('SELECT timing FROM recovery_requests WHERE id=?',(released['request_id'],)).fetchone()[0])==released['timing']
        detail.update(terminal=out['state'],terminal_result=out['result'],all_original_budgets_preserved=True,service_memory_after=memory(parent.pid),seconds=time.monotonic()-start_time)
        return detail,parent
    except Exception:
        if parent.poll() is None:parent.kill();parent.wait(3)
        raise
    finally:
        if child and live(child):os.kill(child,signal.SIGKILL)
        repair()
        for path,data in restore:path.write_bytes(data)

def main():
    from tools.storage_vm import scenario
    if os.geteuid()!=0:raise PermissionError('isolated Linux VM root required')
    os.umask(0o077);source=hashes();out=P/'evidence/admission.json';archive=P/'evidence/admission-attempts';archive.mkdir(exist_ok=True)
    if out.exists():shutil.copyfile(out,archive/(str(time.time_ns())+'.json'))
    def publish(r):
        t=json.dumps(r,indent=2);out.write_text(t);out.with_suffix('.html').write_text('<!doctype html><meta charset="utf-8"><pre>'+html.escape(t)+'</pre>')
    report={'passed':False,'status':'in_progress','cases':[],'scope':'formal source-run root service/executor and real Nginx/TLS, isolated Linux VM; no installed systemd claim','untested':['installed systemd lifecycle','VM reboot','power loss','physical media','arbitrary returned-COMMIT/fsync I/O errors','D-state cleanup','zero downtime']};publish(report)
    try:
        for mode in MATRIX:
            try:r=scenario('sqlite_full','post',check_gate=True,certificate_mode='admission-'+mode)
            except Exception as e:report['cases'].append({'mode':mode,'passed':False,'error':type(e).__name__+': '+str(e)});raise
            report['cases'].append(r);publish(report)
        report.update(passed=True,status='completed')
    except Exception as e:traceback.print_exc();report.update(status='failed',error=type(e).__name__+': '+str(e))
    report.update(source_sha256=source,source_unchanged=source==hashes(),environment={'python':sys.version.split()[0],'kernel':os.uname().release,'machine':os.uname().machine});report['passed']=report['passed'] and report['source_unchanged'];publish(report)
    print(json.dumps({'passed':report['passed'],'cases':len(report['cases']),'error':report.get('error')}));return 0 if report['passed'] else 1
if __name__=='__main__':sys.exit(main())
