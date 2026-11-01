"""Real release preparation, storage failures and dual deadlines; no admission."""
import contextlib,errno,html,json,os,pathlib,shutil,signal,socket,sqlite3,ssl,subprocess,sys,time,traceback
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
from certweft import deadlines
from certweft.core import Writer,run,fingerprint
from certweft.gate import Gate
from certweft.reconciliation import snapshot,digest
from certweft.release import receipt,expected_receipt
from tools.executor_vm import P,hashes,request
MATRIX=['success','source-expired-admit','source-expired-before','source-expired-after','source-expired-result','own-expired-before','completed-source-expiry','crash-before','crash-after','crash-result','stale-before','stale-result','newer-receipt','source-marker-drift','wrong-leaf','bad-http','untrusted-ca','enospc-before','readonly-before','sqlite-full-before','sqlite-full-receipt','sqlite-full-catalog','enospc-after','readonly-after','completed-restart','malformed-receipt']
def source_seconds(mode):return 10 if mode in {'own-expired-before','wrong-leaf','bad-http'} else 3

def settings(work,mode):
    point='release-main-commit' if mode in {'source-expired-before','own-expired-before','crash-before','stale-before'} else 'release-main-committed' if mode in {'source-expired-after','crash-after','newer-receipt','enospc-after','readonly-after'} else 'release-result-commit' if mode in {'source-expired-result','crash-result','stale-result'} else 'release-confirmed' if mode=='sqlite-full-receipt' else 'release-start'
    return {'release_pause_at':point,'release_marker':str(work/'release.json'),'release_pause_once':True}

def exercise(root,work,config,parent,call,normal_job,source,mode):
    child=None;bound=False;filler=None;restore_files=[];cfg=work/'release-config'
    def db(path=None):return contextlib.closing(sqlite3.connect('file:'+str(path or root/'journal.db')+'?mode=ro',uri=True,timeout=.2))
    def main_state():
        with db() as d:return snapshot(d)
    def rootcall(body):return request(config['socket'],body)
    def live(pid):
        try:return pathlib.Path('/proc',str(pid),'stat').read_text().split()[2]!='Z'
        except (FileNotFoundError,ProcessLookupError):return False
    def inventory():return len((work/'executors.jsonl').read_text().splitlines())
    def poll(identity):
        for _ in range(420):
            if parent.poll() is not None:return None
            try:
                reply=rootcall({'op':'recovery-request-status','request_id':identity})
                if reply['ok'] and reply['result']['state'] not in {'ACCEPTED','RUNNING'} and not rootcall({'op':'recovery-status'})['executor_busy']:return reply['result']
            except (OSError,ValueError,EOFError):
                try:parent.wait(4)
                except subprocess.TimeoutExpired:raise
                return None
            time.sleep(.025)
        raise AssertionError('release_stuck')
    def start():
        config.pop('release_pause_at',None);cfg.write_text(json.dumps(config));pathlib.Path(config['socket']).unlink(missing_ok=True)
        log=(work/('release-restart-'+str(time.time_ns())+'.log')).open('wb')
        proc=subprocess.Popen([sys.executable,'-m','certweft.service',str(cfg)],cwd=P,stdout=log,stderr=subprocess.STDOUT);log.close()
        for _ in range(120):
            if proc.poll() is not None:raise AssertionError('release_restart_failed')
            try:
                ready=rootcall({'op':'recovery-status'});assert ready['ok'];proc.fixture_gate_authority=Gate.token(ready['gate']);return proc
            except (OSError,EOFError):time.sleep(.025)
        proc.kill();proc.wait();raise AssertionError('release_restart_timeout')
    def expire(budget):
        left=(budget['expires_boot_ns']-deadlines.now_ns())/1e9
        if left>0:time.sleep(left+.025)
    def observe():
        ctx=ssl.create_default_context(cafile=str(work/'ca.pem'))
        with socket.create_connection((config['writer']['ip'],config['writer']['port']),2) as raw:
            with ctx.wrap_socket(raw,server_hostname='localhost') as tls:
                leaf=__import__('hashlib').sha256(tls.getpeercert(True)).hexdigest();tls.sendall(b'GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n');return leaf,tls.recv(4096).split(b'\r\n')[0]
    def repair_fault():
        nonlocal bound,filler
        if bound:run(['umount',root]);bound=False
        if filler:filler.unlink();filler=None
        if mode=='sqlite-full-catalog':
            with contextlib.closing(sqlite3.connect(root/'recovery.db')) as d,d:d.execute('DROP TRIGGER IF EXISTS release_full');d.execute('DROP TABLE IF EXISTS release_pressure')
    try:
        before=main_state();core=json.loads(before['state'][0][1]);gate=Gate(root).read();pointer=os.readlink(root/'active.conf')
        versions={str(p.relative_to(root)):digest(p.read_bytes().hex()) for v in root.glob('v-*') for p in v.iterdir() if p.is_file()}
        body={'op':'prepare-release','request_id':'release-one','opening_request_id':source['request_id'],'opening_marker_digest':source['result']['marker_digest'],'timeout_seconds':1 if mode=='own-expired-before' else 10,**Gate.token(gate)}
        detail={'mode':mode,'formal_service':True,'updates_enabled':False};out=None
        if mode=='source-expired-admit':
            expire(source['timing']['budget']);denied=rootcall(body);assert not denied['ok'] and denied['error']=='Expired'
            with db(root/'recovery.db') as d:assert not d.execute("SELECT 1 FROM recovery_requests WHERE id='release-one'").fetchone()
            detail['expired_source_not_admitted']=True
        else:
            denied=call(config['socket'],body);assert not denied['ok'] and denied['reason']=='admin_required'
            accepted=rootcall(body);assert accepted['ok'] and accepted['created'];original=accepted['result']
            assert original['target']['source_budget']==source['timing']['budget']
            for _ in range(200):
                if (work/'release.json').exists():child=json.loads((work/'release.json').read_text())['pid'];break
                time.sleep(.02)
            else:raise AssertionError('release_checkpoint_missing')
            locked=mode in {'source-expired-before','own-expired-before','crash-before','stale-before','source-expired-result','crash-result','stale-result'}
            if not locked:
                same=rootcall(body);assert not same['created'] and same['result']['timing']==original['timing'] and same['result']['target']==original['target']
                conflict=rootcall({**body,'timeout_seconds':9});assert not conflict['ok'] and conflict['reason']=='request_conflict'
                detail['dedup_preserves_both_original_budgets']=True
            if mode=='source-marker-drift':
                with contextlib.closing(sqlite3.connect(root/'journal.db')) as d,d:
                    r=json.loads(d.execute('SELECT record FROM opening_intent').fetchone()[0]);r['request_id']='newer-opening';d.execute('UPDATE opening_intent SET record=?',(json.dumps(r),))
            if mode in {'newer-receipt','malformed-receipt','sqlite-full-receipt'}:
                with contextlib.closing(sqlite3.connect(root/'journal.db')) as d,d:
                    if mode=='newer-receipt':
                        newer=receipt(d);newer['request_id']='newer-release';d.execute('UPDATE release_preparation SET record=?',(json.dumps(newer),))
                    else:
                        d.execute('CREATE TABLE release_preparation(id INTEGER PRIMARY KEY,record TEXT)')
                        initial='{}' if mode=='malformed-receipt' else json.dumps(expected_receipt(original,fingerprint(root/('v-'+core['committed'])/'cert.pem'),core['committed']))
                        d.execute('INSERT INTO release_preparation VALUES(1,?)',(initial,))
                        if mode=='sqlite-full-receipt':d.execute('CREATE TABLE release_pressure(data BLOB)');d.execute('CREATE TRIGGER release_full BEFORE INSERT ON release_preparation BEGIN INSERT INTO release_pressure VALUES(zeroblob(1048576)); END')
            if mode=='sqlite-full-before':
                with contextlib.closing(sqlite3.connect(root/'journal.db')) as d,d:d.execute('CREATE TABLE release_pressure(data BLOB)');d.execute('CREATE TRIGGER release_full BEFORE UPDATE ON storage_probe BEGIN INSERT INTO release_pressure VALUES(zeroblob(1048576)); END')
            if mode=='sqlite-full-catalog':
                with contextlib.closing(sqlite3.connect(root/'recovery.db')) as d,d:d.execute('CREATE TABLE release_pressure(data BLOB)');d.execute("CREATE TRIGGER release_full BEFORE UPDATE ON recovery_requests WHEN NEW.state='RELEASE_VERIFIED_CLOSED' BEGIN INSERT INTO release_pressure VALUES(zeroblob(1048576)); END")
            if mode.startswith('enospc'):
                filler=root/'release-filler'
                with filler.open('wb',buffering=0) as f:
                    try:
                        while True:f.write(b'x'*4096)
                    except OSError as e:assert e.errno==errno.ENOSPC;detail['observed_errno']=e.errno
                try:
                    with (root/'release-full-probe').open('wb',buffering=0) as f:f.write(b'x'*4096);os.fsync(f.fileno())
                except OSError as e:assert e.errno==errno.ENOSPC
                else:raise AssertionError('enospc_not_real')
            if mode.startswith('readonly'):
                run(['mount','--bind',root,root]);bound=True;run(['mount','-o','remount,bind,ro',root])
                try:(root/'release-ro-probe').write_bytes(b'x')
                except OSError as e:assert e.errno==errno.EROFS;detail['observed_errno']=e.errno
                else:raise AssertionError('readonly_not_real')
            if mode=='untrusted-ca':
                ca=pathlib.Path(config['writer']['ca']);restore_files.append((ca,ca.read_bytes()))
                run(['openssl','req','-new','-x509','-key',work/'ca-key','-subj','/CN=Wrong CA','-addext','basicConstraints=critical,CA:TRUE','-out',work/'wrong-ca.pem']);ca.write_bytes((work/'wrong-ca.pem').read_bytes())
            if mode=='wrong-leaf':
                other=next(v for v in root.glob('v-*') if v.name!='v-'+core['committed']);tmp=root/'fixture-select';tmp.symlink_to(other.name+'/tls.conf');os.replace(tmp,root/'active.conf');run(['/usr/sbin/nginx','-s','reload','-c',config['writer']['conf']])
                for _ in range(100):
                    if observe()[0]!=fingerprint(root/('v-'+core['committed'])/'cert.pem'):break
                    time.sleep(.02)
                else:raise AssertionError('wrong_leaf_not_live')
                tmp.symlink_to(pointer);os.replace(tmp,root/'active.conf')
            if mode=='bad-http':
                conf=pathlib.Path(config['writer']['conf']);restore_files.append((conf,conf.read_bytes()));conf.write_text(conf.read_text().replace('return 200 "ok"','return 503 "bad"'));run(['/usr/sbin/nginx','-s','reload','-c',conf])
                for _ in range(100):
                    if observe()[1].startswith(b'HTTP/1.1 503'):break
                    time.sleep(.02)
                else:raise AssertionError('bad_http_not_live')
            if mode.startswith('source-expired'):expire(source['timing']['budget'])
            if mode=='own-expired-before':expire(original['timing']['budget'])
            if mode.startswith('stale'):new_gate=Gate(root).start()
            if mode.startswith('crash'):
                with db() as d:published=receipt(d)
                with db(root/'recovery.db') as d:assert d.execute("SELECT state FROM recovery_requests WHERE id='release-one'").fetchone()[0]=='RUNNING'
                assert (published is not None)==(mode!='crash-before')
                os.kill(parent.pid,signal.SIGKILL);parent.wait(3)
                competing=subprocess.run([sys.executable,'-m','certweft.service',str(work/'certificate-config')],cwd=P,capture_output=True,timeout=3);assert competing.returncode==73
                os.kill(child,signal.SIGKILL)
                for _ in range(100):
                    if not live(child):break
                    time.sleep(.02)
                else:raise AssertionError('old_release_executor_alive')
                count=inventory();parent=start();out=poll(body['request_id']);assert out['state'] in {'INTERRUPTED','EXPIRED'} and inventory()==count
                stale=rootcall({**body,'request_id':'old-release'});assert not stale['ok'] and stale['reason']=='stale_gate_authority'
                detail.update(pending_observed_before_kill=True,old_executor_fences_takeover=True,no_automatic_replay=True)
            else:
                os.kill(child,signal.SIGCONT);out=poll(body['request_id']);repair_fault()
                if out is None:
                    assert mode.startswith(('readonly','enospc')) and parent.wait(3)==75
                    parent=start();out=poll(body['request_id']);assert out['state'] in {'FAILED','INTERRUPTED','EXPIRED'};detail['unrecordable_fault_failstop']=True
                expected='EXPIRED' if mode.startswith('source-expired') or mode=='own-expired-before' else 'FAILED' if mode in {'newer-receipt','source-marker-drift','wrong-leaf','bad-http','untrusted-ca','sqlite-full-before','sqlite-full-receipt','sqlite-full-catalog','malformed-receipt'} or mode.startswith('stale') else 'RELEASE_VERIFIED_CLOSED'
                if mode.startswith(('readonly','enospc')):
                    assert out['state'] in {'FAILED','INTERRUPTED','EXPIRED'}
                    if not detail.get('unrecordable_fault_failstop'):
                        assert out['state']=='FAILED' and out['result']['errno']==(errno.EROFS if mode.startswith('readonly') else errno.ENOSPC)
                        assert out['result']['failure_stage']==('result_publication' if mode.endswith('after') else 'storage_validation')
                    assert not rootcall({'op':'recovery-status'})['release_prepared_closed'];detail['storage_fault_never_success']=True
                else:assert out['state']==expected,(mode,out)
                if mode.startswith('sqlite-full'):assert out['result']['sqlite_error']=='SQLITE_FULL'
                if mode=='sqlite-full-catalog':
                    assert out['result']['observed_storage_verified'] and out['result']['observed_tls_confirmed'] and out['result']['receipt_commit_observed']
                    assert out['result']['failure_stage']=='result_publication'
                    with db() as d:assert receipt(d) is not None
                    detail['durable_receipt_without_root_completion_never_qualifies']=True
                if mode=='sqlite-full-receipt':
                    assert out['result']['observed_storage_verified'] and out['result']['observed_tls_confirmed'] and not out['result']['receipt_commit_observed']
                    assert out['result']['failure_stage']=='receipt_publication'
                    with db() as d:assert d.execute('SELECT record FROM release_preparation').fetchone()[0]==initial
                if mode=='sqlite-full-before':assert out['result']['failure_stage']=='storage_validation' and not out['result']['observed_storage_verified']
                if mode in {'wrong-leaf','bad-http'}:assert out['result']['failure_stage']=='tls_confirmation' and out['result']['reason']=='confirmation_timeout'
                if mode=='untrusted-ca':assert out['result']['failure_stage']=='certificate_validation' and out['result']['error']=='CalledProcessError' and out['result']['observed_storage_verified']
                if mode.startswith('stale'):assert Gate(root).read()==new_gate and out['result']['reason']=='stale_gate_authority'
                if mode in {'source-expired-before','own-expired-before','stale-before'}:
                    with db() as d:assert receipt(d) is None
                if mode in {'source-expired-after','source-expired-result','stale-result'}:
                    with db() as d:assert receipt(d) is not None
                if mode=='source-marker-drift':assert out['result']['reason']=='opening_source_mismatch'
                if mode=='newer-receipt':
                    assert out['result']['reason']=='stale_release_receipt'
                    with db() as d:assert receipt(d)==newer
                if mode=='malformed-receipt':
                    assert out['result']['reason']=='release_receipt_schema'
                    with db() as d:assert d.execute('SELECT record FROM release_preparation').fetchone()[0]=='{}'
                if expected=='RELEASE_VERIFIED_CLOSED' and not mode.startswith(('readonly','enospc')):
                    with db() as d:assert digest(receipt(d))==out['result']['receipt_digest']
                    assert rootcall({'op':'recovery-status'})['release_prepared_closed']
                    detail['fresh_storage_certificate_tls_and_pair_verified']=True
                    if mode=='completed-source-expiry':expire(source['timing']['budget']);assert not rootcall({'op':'recovery-status'})['release_prepared_closed']
                    if mode=='completed-restart':
                        count=inventory();os.kill(parent.pid,signal.SIGKILL);parent.wait(3);parent=start();assert inventory()==count
                        assert not rootcall({'op':'recovery-status'})['release_prepared_closed']
            assert out['timing']==original['timing'] and out['target']==original['target']
            count=inventory();replay=rootcall(body);assert not replay['created'] and replay['result']==out and inventory()==count
            with db(root/'recovery.db') as d:assert json.loads(d.execute('SELECT timing FROM recovery_requests WHERE id=?',(source['request_id'],)).fetchone()[0])==source['timing']
            if out['state']!='RELEASE_VERIFIED_CLOSED':assert not rootcall({'op':'recovery-status'})['release_prepared_closed']
            detail.update(terminal=out['state'],terminal_result=out['result'],both_original_budgets_preserved=True)
        assert main_state()==before and os.readlink(root/'active.conf')==pointer
        assert {str(p.relative_to(root)):digest(p.read_bytes().hex()) for v in root.glob('v-*') for p in v.iterdir() if p.is_file()}==versions
        core_now=json.loads(main_state()['state'][0][1]);normal={**normal_job,'request_id':'release-never-admits','epoch':core_now['epoch'],'revision':core_now['revision']}
        denied=call(config['socket'],normal);assert not denied['ok'] and denied['reason'] in {'stale_gate_authority','recovery_required'}
        assert Gate(root).read()['state'] in {'VERIFIED_CLOSED','RECOVERY_REQUIRED'} and not rootcall({'op':'recovery-status'})['gate_allows_updates']
        detail.update(main_history_and_health_unchanged=True,normal_updates_rejected=True);return detail,parent
    except Exception:
        if parent.poll() is None:parent.kill();parent.wait(3)
        raise
    finally:
        if child and live(child):os.kill(child,signal.SIGKILL)
        repair_fault()
        for path,content in restore_files:path.write_bytes(content)

def main():
    from tools.storage_vm import scenario
    if os.geteuid()!=0:raise PermissionError('isolated Linux VM root required')
    os.umask(0o077);source=hashes();out=P/'evidence/release-preparation.json';archive=P/'evidence/release-attempts';archive.mkdir(exist_ok=True)
    if out.exists():shutil.copyfile(out,archive/(str(time.time_ns())+'.json'))
    def publish(r):
        text=json.dumps(r,indent=2);out.write_text(text);out.with_suffix('.html').write_text('<!doctype html><meta charset="utf-8"><pre>'+html.escape(text)+'</pre>')
    report={'passed':False,'status':'in_progress','cases':[],'scope':'formal release executor and service, fresh filesystem/SQLite/OpenSSL/TLS in isolated Linux VM; Gate remains closed','untested':['actual admission release','installed systemd lifecycle','VM reboot','power loss','physical media','arbitrary returned-COMMIT/fsync I/O errors','D-state cleanup','zero downtime']};publish(report)
    try:
        for mode in MATRIX:
            try:detail=scenario('sqlite_full','post',check_gate=True,certificate_mode='release-'+mode)
            except Exception as e:report['cases'].append({'mode':mode,'passed':False,'error':type(e).__name__+': '+str(e)});raise
            report['cases'].append(detail);publish(report)
        report.update(passed=True,status='completed')
    except Exception as e:traceback.print_exc();report.update(status='failed',error=type(e).__name__+': '+str(e))
    report.update(source_sha256=source,source_unchanged=source==hashes(),environment={'python':sys.version.split()[0],'kernel':os.uname().release,'machine':os.uname().machine});report['passed']=report['passed'] and report['source_unchanged'];publish(report)
    print(json.dumps({'passed':report['passed'],'cases':len(report['cases']),'error':report.get('error')}));return 0 if report['passed'] else 1
if __name__=='__main__':sys.exit(main())
