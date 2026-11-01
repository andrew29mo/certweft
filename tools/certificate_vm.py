"""Real committed-certificate recovery; completed results remain isolated."""
import contextlib,hashlib,html,json,os,pathlib,shutil,signal,socket,sqlite3,ssl,subprocess,sys,time,traceback
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
from certweft.core import Writer,run,fingerprint
from certweft.gate import Gate
from certweft import deadlines
from tools.executor_vm import request,hashes
P=pathlib.Path(__file__).resolve().parents[1]

def exercise(root,work,config,parent,call,normal_job,mode):
    child=None;cfg=work/'certificate-config';writer=Writer(**config['writer'])
    def live(pid):
        try:return pathlib.Path('/proc',str(pid),'stat').read_text().split()[2]!='Z'
        except (FileNotFoundError,ProcessLookupError):return False
    def logical():
        with contextlib.closing(sqlite3.connect(root/'journal.db')) as db:
            values={name:db.execute('SELECT * FROM '+name+' ORDER BY id').fetchall() for name in ['state','health','requests']}
        return hashlib.sha256(repr(values).encode()).hexdigest()
    def generations():return {str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for d in root.glob('v-*') for p in d.iterdir() if p.is_file()}
    def observe():
        context=ssl.create_default_context(cafile=config['writer']['ca'])
        with socket.create_connection((config['writer']['ip'],config['writer']['port']),2) as raw:
            with context.wrap_socket(raw,server_hostname=config['writer']['host']) as tls:
                assert not tls.session_reused;leaf=hashlib.sha256(tls.getpeercert(True)).hexdigest()
                tls.sendall(b'GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n');data=b''
                while b'\r\n\r\n' not in data:
                    part=tls.recv(1024);assert part;data+=part;assert len(data)<=4096
                return leaf,data.split(b'\r\n',1)[0].decode()
    def root_call(body):return request(config['socket'],body)
    def count():return len((work/'executors.jsonl').read_text().splitlines())
    def start(frozen):
        pathlib.Path(config['socket']).unlink(missing_ok=True);cfg.write_text(json.dumps(frozen))
        log=(work/('certificate-service-'+str(time.time_ns())+'.log')).open('wb')
        proc=subprocess.Popen([sys.executable,'-m','certweft.service',str(cfg)],cwd=P,stdout=log,stderr=subprocess.STDOUT);log.close()
        for _ in range(120):
            if proc.poll() is not None:raise AssertionError('certificate_startup')
            try:
                ready=request(config['socket'],{'op':'recovery-status'})
                assert ready.get('ok'),ready
                proc.fixture_gate_authority=Gate.token(ready['gate']);return proc
            except (OSError,EOFError):time.sleep(.025)
        proc.kill();proc.wait();raise AssertionError('certificate_endpoint')
    def poll(identity):
        for _ in range(300):
            response=root_call({'op':'recovery-request-status','request_id':identity});assert response['ok'];row=response['result']
            if row['state'] not in {'ACCEPTED','RUNNING','CERTIFICATE_VERIFIED'} and not root_call({'op':'recovery-status'})['executor_busy']:return row
            time.sleep(.025)
        raise AssertionError('certificate_operation_stuck')
    points={'wrong-leaf':'restore-reloaded','bad-http':'restore-reloaded','crash-selected':'restore-selected','crash-reloaded':'restore-reloaded','crash-confirmed':'restore-confirmed','crash-proof':'certificate-proof','crash-gate':'closed-gate-published','expired-tls':'restore-confirmed','expired-commit':'closed-result-commit'}
    frozen={k:v for k,v in config.items() if k not in {'pause_at','storage_latch_marker','unrecorded_storage_marker','gate_stop_sync_eio'}}
    frozen.update(verification_pause_at=points.get(mode,'restore-validated') if not mode.startswith('invalid-') else 'restoration-start',verification_marker=str(work/'certificate-marker.json'),verification_pause_once=True)
    if mode.startswith(('opening-','release-','admission-')):
        from tools.reconcile_vm import settings as preparation_settings
        from tools.opening_vm import settings as opening_settings
        frozen.update(preparation_settings(work,'latched'));frozen.update(opening_settings(work,mode.removeprefix('opening-') if mode.startswith('opening-') else 'success'))
        frozen['sqlite_max_pages']=config['sqlite_max_pages']+(12 if mode.startswith('admission-') else 8 if mode.startswith('release-') else 4)
        if mode.startswith(('release-','admission-')):

            from tools.release_vm import settings as release_settings
            frozen.update(release_settings(work,mode.removeprefix('release-') if mode.startswith('release-') else 'success'))
        if mode.startswith('admission-'):
            from tools.admission_vm import settings as admission_settings
            frozen.update(admission_settings(work,mode.removeprefix('admission-')))
    if mode.startswith('reconcile-'):
        from tools.reconcile_vm import settings
        frozen.update(settings(work,mode.removeprefix('reconcile-')))
    try:
        parent.terminate();parent.wait(3)
        state=writer.status();name=state['committed'];directory=root/('v-'+name)
        expected=fingerprint(directory/'cert.pem');before_wire=observe();before_pointer=os.readlink(root/'active.conf')
        if mode.startswith('invalid-'):
            if mode=='invalid-key':
                key=work/'invalid-key';run(['openssl','ecparam','-name','prime256v1','-genkey','-noout','-out',key]);(directory/'key.pem').write_bytes(key.read_bytes())
            else:
                ext=work/'invalid-ext';bad=work/'invalid-cert'
                ext.write_text(('subjectAltName=DNS:other.invalid' if mode=='invalid-san' else 'subjectAltName=DNS:localhost')+'\n'+('extendedKeyUsage=clientAuth' if mode=='invalid-eku' else 'extendedKeyUsage=serverAuth')+'\nbasicConstraints=critical,CA:FALSE\n')
                run(['openssl','x509','-req','-in',work/'req','-CA',config['writer']['ca'],'-CAkey',work/'ca-key','-sha256','-set_serial','77','-days','-1' if mode=='invalid-expired' else '1','-extfile',ext,'-out',bad]);(directory/'cert.pem').write_bytes(bad.read_bytes())
            # A valid structural digest is deliberate: crypto rejection must not
            # be accidentally satisfied solely by content-drift rejection.
            state['committed_digest']=writer.digest(name)
            with contextlib.closing(sqlite3.connect(root/'journal.db')) as db,db:db.execute('UPDATE state SET data=?',(json.dumps(state),))
        protected=logical();version_bytes=generations();parent=start(frozen)
        gate=root_call({'op':'recovery-status'})['gate'];assert gate['state']=='RECOVERY_REQUIRED'
        gate=root_call({'op':'prepare-recovery',**Gate.token(gate)})['gate']
        body={'op':'recover-certificate','request_id':'restore-one','timeout_seconds':1 if mode.startswith('expired') else 10,**Gate.token(gate)}
        denied=call(config['socket'],body);assert not denied['ok'] and denied['reason']=='admin_required'
        accepted=root_call(body);assert accepted['ok'] and accepted['created'];original=accepted['result']
        for _ in range(180):
            if (work/'certificate-marker.json').exists():child=json.loads((work/'certificate-marker.json').read_text())['pid'];break
            time.sleep(.02)
        else:raise AssertionError('certificate_checkpoint_missing')
        assert live(child)
        detail={'mode':mode,'root_only':True,'fixed_committed_target':True}
        if mode not in {'crash-gate','expired-commit'}:
            duplicate=root_call(body);assert duplicate['ok'] and not duplicate['created'] and duplicate['result']['timing']==original['timing']
            conflict=root_call({**body,'op':'verify-storage'});assert not conflict['ok'] and conflict['reason']=='request_conflict'
            detail['inflight_replay_and_kind_conflict_verified']=True
        else:
            with contextlib.closing(sqlite3.connect('file:'+str(root/'recovery.db')+'?mode=ro',uri=True)) as db:
                assert db.execute("SELECT state FROM recovery_requests WHERE id='restore-one'").fetchone()[0]=='CERTIFICATE_VERIFIED'
            assert Gate(root).read()['state']=='VERIFIED_CLOSED';detail['partial_publication_not_durable_completion']=True
        if mode=='wrong-leaf':
            assert state['candidate'] is not None
            temporary=root/'fixture-select';temporary.symlink_to('v-'+state['candidate']+'/tls.conf');os.replace(temporary,root/'active.conf')
            run(['/usr/sbin/nginx','-s','reload','-c',config['writer']['conf']])
            for _ in range(100):
                if observe()[0]==fingerprint(work/'new.pem'):break
                time.sleep(.03)
            else:raise AssertionError('wrong_leaf_not_observed')
        if mode=='bad-http':
            conf=pathlib.Path(config['writer']['conf']);conf.write_text(conf.read_text().replace('return 200 "ok"','return 503 "not-ready"'))
            run(['/usr/sbin/nginx','-s','reload','-c',conf])
            for _ in range(100):
                if observe()[1].startswith('HTTP/1.1 503 '):break
                time.sleep(.03)
            else:raise AssertionError('bad_http_not_observed')
        if mode.startswith('crash-'):
            os.kill(parent.pid,signal.SIGKILL);parent.wait(3)
            with contextlib.closing(sqlite3.connect('file:'+str(root/'recovery.db')+'?mode=ro',uri=True)) as db:
                pending=db.execute("SELECT state,timing FROM recovery_requests WHERE id='restore-one'").fetchone();assert pending[0] in {'RUNNING','CERTIFICATE_VERIFIED'} and json.loads(pending[1])==original['timing']
            snapshot=Gate(root).read();competing=subprocess.run([sys.executable,'-m','certweft.service',str(cfg)],cwd=P,capture_output=True,timeout=3);assert competing.returncode==73 and Gate(root).read()==snapshot
            os.kill(child,signal.SIGKILL)
            for _ in range(100):
                if not live(child):break
                time.sleep(.02)
            else:raise AssertionError('old_restore_executor_alive')
            frozen.pop('verification_pause_at');before_count=count();parent=start(frozen)
            row=poll('restore-one');assert row['state'] in {'INTERRUPTED','EXPIRED'} and row['timing']==original['timing'] and row['target']==original['target']
            assert not root_call(body)['created'] and count()==before_count
            stale=root_call({**body,'request_id':'old-authority'});assert not stale['ok'] and stale['reason']=='stale_gate_authority'
            current=root_call({'op':'recovery-status'});assert current['gate']['state']=='RECOVERY_REQUIRED' and not current['completion_recorded']
            gate=root_call({'op':'prepare-recovery',**Gate.token(current['gate'])})['gate'];retry={**body,**Gate.token(gate),'request_id':'explicit-fresh-restore','timeout_seconds':10}
            assert root_call(retry)['created'];row=poll(retry['request_id']);assert row['state']=='VERIFIED_CLOSED'
            detail.update(unfinished_control_observed_before_restart=True,old_executor_fences_takeover=True,no_replay_or_budget_reset=True,explicit_fresh_intent_restores=True)
        else:
            if mode.startswith('expired'):
                left=deadlines.remaining(original['timing']['budget']);assert left>0;time.sleep(left+.04)
            os.kill(child,signal.SIGCONT);row=poll(body['request_id'])
            expected_state='FAILED' if mode.startswith('invalid-') or mode in {'wrong-leaf','bad-http'} else 'EXPIRED' if mode.startswith('expired') else 'VERIFIED_CLOSED'
            assert row['state']==expected_state and row['timing']==original['timing']
            before_count=count();assert not root_call(body)['created'] and count()==before_count
            if mode.startswith('invalid-'):
                assert observe()==before_wire and os.readlink(root/'active.conf')==before_pointer
                assert not row['result']['may_have_changed_service']
                assert row['result']['failure_stage']=='certificate_validation'
                assert (row['result']['error'],row['result']['reason'])==(('Rejected','key_mismatch') if mode=='invalid-key' else ('CalledProcessError',None))
                detail['invalid_but_digest_consistent_certificate_rejected_before_select']=True
            if mode in {'wrong-leaf','bad-http'}:
                assert not row['result']['restored']
                assert row['result']['failure_stage']=='tls_confirmation'
                assert (row['result']['error'],row['result']['reason'])==('Rejected','confirmation_timeout')
                detail['fresh_tls_or_http_confirmation_rejected']=True
            if mode.startswith('expired'):
                assert not row['result']['restored'] and not root_call({'op':'recovery-status'})['completion_recorded'];detail['expiry_never_commits_completion']=True
        if row['state']=='VERIFIED_CLOSED':
            assert observe()==(expected,'HTTP/1.1 200 OK')
            assert os.readlink(root/'active.conf')=='v-'+name+'/tls.conf'
            current=root_call({'op':'recovery-status'});assert current['gate']['state']=='VERIFIED_CLOSED' and current['completion_recorded'] and not current['gate_allows_updates']
            assert row['result']['fingerprint']==expected and row['result']['committed']==name and row['result']['restored'] and not row['result']['updates_enabled']
            detail.update(committed_pointer_and_new_tls_verified=True,paired_completion_recorded=True)
            if mode=='success-latched':
                assert row['result']['prior_health']=='STORAGE_FAILED'
                with contextlib.closing(sqlite3.connect(root/'journal.db')) as db:assert db.execute('SELECT state FROM health WHERE id=1').fetchone()[0]=='STORAGE_FAILED'
                detail['storage_failure_latch_preserved']=True
            if mode=='committed':assert expected==fingerprint(work/'new.pem') and expected!=fingerprint(work/'old.pem');detail['new_committed_leaf_not_rolled_back_to_older_generation']=True
        if mode=='success-restart':
            completed=row;before_count=count();os.kill(parent.pid,signal.SIGKILL);parent.wait(3)
            frozen.pop('verification_pause_at');parent=start(frozen)
            current=root_call({'op':'recovery-status'});assert current['gate']['state']=='RECOVERY_REQUIRED' and not current['completion_recorded']
            replay=root_call(body);assert not replay['created'] and replay['result']==completed and count()==before_count
            assert observe()==(expected,'HTTP/1.1 200 OK')
            detail.update(completed_history_preserved_without_replay=True,restart_never_opens_even_after_completed_restoration=True)
        assert logical()==protected and generations()==version_bytes
        refused=call(config['socket'],{**normal_job,'request_id':'still-isolated'});assert not refused['ok']
        assert Gate(root).read()['state'] in {'VERIFY_REQUIRED','VERIFIED_CLOSED','RECOVERY_REQUIRED'}
        if mode.startswith('reconcile-'):
            from tools.reconcile_vm import exercise as prepare_journal
            detail['journal_preparation'],parent=prepare_journal(root,work,frozen,parent,call,normal_job,row,mode.removeprefix('reconcile-'))
        if mode.startswith(('opening-','release-','admission-')):
            from tools.reconcile_vm import exercise as prepare_journal
            from tools.opening_vm import exercise as opening_exercise
            preparation,parent=prepare_journal(root,work,frozen,parent,call,normal_job,row,'latched')
            prepared=root_call({'op':'recovery-request-status','request_id':'prepare-one'})['result']
            detail['journal_preparation']=preparation
            if mode.startswith(('release-','admission-')):
                from tools.release_vm import exercise as release_exercise,source_seconds
                release_mode=mode.removeprefix('release-') if mode.startswith('release-') else 'success'
                detail['opening_intent'],parent=opening_exercise(root,work,frozen,parent,call,normal_job,prepared,'success',10 if mode.startswith('admission-') else source_seconds(release_mode))
                source=root_call({'op':'recovery-request-status','request_id':'opening-one'})['result']
                detail['release_preparation'],parent=release_exercise(root,work,frozen,parent,call,normal_job,source,release_mode,3 if mode=='admission-expired-release' else None)
                if mode.startswith('admission-'):
                    from tools.admission_vm import exercise as admission_exercise
                    released=root_call({'op':'recovery-request-status','request_id':'release-one'})['result']
                    detail['admission'],parent=admission_exercise(root,work,frozen,parent,call,normal_job,released,mode.removeprefix('admission-'))
            else:detail['opening_intent'],parent=opening_exercise(root,work,frozen,parent,call,normal_job,prepared,mode.removeprefix('opening-'))
        detail['terminal_result']=row['result']
        detail.update(terminal=row['state'],certificate_stage_logical_journal_unchanged=True,certificate_stage_immutable_generations_unchanged=True,certificate_stage_updates_enabled=False)
        detail['updates_enabled']=root_call({'op':'recovery-status'})['gate_allows_updates']
        return detail,parent
    except Exception:
        if child and live(child):os.kill(child,signal.SIGKILL)
        if parent.poll() is None:parent.terminate()
        try:parent.wait(3)
        except subprocess.TimeoutExpired:parent.kill();parent.wait()
        raise

def main():
    from tools.storage_vm import scenario
    if os.geteuid()!=0:raise PermissionError('isolated VM root required')
    os.umask(0o077);source=hashes();out=P/'evidence/certificate-recovery.json'
    if out.exists():
        archive=P/'evidence/certificate-attempts';archive.mkdir(exist_ok=True);shutil.copyfile(out,archive/(str(time.time_ns())+'.json'))
    def publish(r):
        text=json.dumps(r,indent=2);out.write_text(text);out.with_suffix('.html').write_text('<!doctype html><meta charset="utf-8"><pre>'+html.escape(text)+'</pre>')
    report={'passed':False,'status':'in_progress','cases':[],'scope':'formal source-run service + lease-fenced certificate recovery executor; actual Nginx pidfd reload and new TLS in isolated Linux VM','untested':['normal admission unlock','normal request reconciliation/health reset','persistent systemd deployment','VM reboot','power loss','physical media faults','D-state cleanup']};publish(report)
    matrix=['success','success-restart','success-latched','committed','invalid-expired','invalid-san','invalid-eku','invalid-key','wrong-leaf','bad-http','expired-tls','expired-commit','crash-selected','crash-reloaded','crash-confirmed','crash-proof','crash-gate']
    try:
        for mode in matrix:
            try:detail=scenario('sqlite_full' if mode=='success-latched' else 'enospc','pre' if mode=='committed' else 'post',check_gate=True,certificate_mode=mode)
            except Exception as error:
                report['cases'].append({'mode':mode,'passed':False,'error':type(error).__name__+': '+str(error)});raise
            report['cases'].append(detail);publish(report)
        report['passed']=True;report['status']='completed'
    except Exception as error:traceback.print_exc();report['error']=type(error).__name__+': '+str(error);report['status']='failed'
    report['source_sha256']=source;report['source_unchanged']=source==hashes();report['passed']=report['passed'] and report['source_unchanged'];report['environment']={'python':sys.version.split()[0],'kernel':os.uname().release,'machine':os.uname().machine};publish(report)
    print(json.dumps({'passed':report['passed'],'cases':len(report['cases']),'error':report.get('error')}));return 0 if report['passed'] else 1
if __name__=='__main__':sys.exit(main())
