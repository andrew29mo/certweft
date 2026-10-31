"""Run only as root inside disposable Linux VM. Private fixture never exported."""
import socket,ssl,threading
import hashlib,html,json,os,pathlib,platform,signal,subprocess,sys,tempfile,time,traceback,resource
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
from unittest.mock import patch
from certweft.ca import reissue
from certweft.core import Writer,validate,probe,fingerprint,Rejected,run
P=pathlib.Path(__file__).resolve().parents[1]
def source_hashes():
    return {str(f.relative_to(P)):hashlib.sha256(f.read_bytes()).hexdigest()
            for d in ['certweft','tools','tests'] for f in (P/d).glob('*.py')}
START_HASHES=source_hashes()

def main():
    report={'passed':False,'cases':[],'platform':platform.platform(),'scope':'Linux VM; private loopback fixture; process crashes, not power loss','untested':['systemd installation','VM reboot','power loss','untrusted worker privilege separation','missing intermediate wire negative','clock jumps','long-term rotation','serverAuth-only renew token compatibility','privileged helper exec inheritance','post-publication physical ENOSPC','expired rollback certificate']}
    start=time.monotonic();work=pathlib.Path(tempfile.mkdtemp(prefix='certweft-',dir='/var/tmp'));os.chmod(work,0o700)
    ca=None;ng=None
    out=P/'evidence/exploration.json'
    if out.exists():
        attempts=P/'evidence/attempts';attempts.mkdir(exist_ok=True)
        (attempts/(str(time.time_ns())+'.json')).write_bytes(out.read_bytes())
    marker=json.dumps({'passed':False,'status':'in_progress'})
    out.with_suffix('.html').write_text('<!doctype html><meta charset="utf-8"><pre>'+html.escape(marker)+'</pre>')
    out.write_text(marker)
    def case(name,fn):
        t=time.monotonic()
        try:
            detail=fn();detail=detail.decode() if isinstance(detail,bytes) else detail;report['cases'].append(dict(name=name,passed=True,seconds=time.monotonic()-t,detail=detail))
        except Exception as e:
            report['cases'].append(dict(name=name,passed=False,error=type(e).__name__))
            raise
    def reject(fn):
        try:fn()
        except (Rejected,subprocess.CalledProcessError,BlockingIOError):return 'rejected'
        raise AssertionError('unexpected acceptance')
    try:
        step=os.environ['CW_STEP'];stepca=os.environ['CW_CA'];os.environ['STEPPATH']=str(work/'ca')
        (work/'password').write_text('disposable-test-only')
        run([step,'ca','init','--name','Certweft exploration','--dns','localhost','--address','127.0.0.1:19090','--provisioner','exploration','--password-file',work/'password'],20)
        template=work/'server.tpl'
        template.write_text('{"subject":{{ toJson .Subject }},"sans":[{"type":"dns","value":"localhost"}],"keyUsage":["digitalSignature"],"extKeyUsage":["serverAuth"]}')
        cfgpath=work/'ca/config/ca.json';cfg=json.loads(cfgpath.read_text())
        cfg['authority']['provisioners'][0]['options']={'x509':{'templateFile':str(template)}}
        cfgpath.write_text(json.dumps(cfg))
        ca=subprocess.Popen([stepca,str(work/'ca/config/ca.json'),'--password-file',str(work/'password')],stdout=open(work/'ca.log','wb'),stderr=subprocess.STDOUT)
        root=work/'ca/certs/root_ca.crt'
        for _ in range(100):
            try:run([step,'ca','health','--ca-url','https://localhost:19090','--root',root]);break
            except Exception:time.sleep(.1)
        else:raise AssertionError('CA not ready')
        run([step,'ca','certificate','localhost',work/'initial.pem',work/'initial.key','--ca-url','https://localhost:19090','--root',root,'--provisioner','exploration','--provisioner-password-file',work/'password'],15)
        # Server-only template is enforced by the real CA policy.
        w=Writer(work/'store','/usr/sbin/nginx',work/'nginx.conf',root,work/'initial.key','localhost','127.0.0.1',19443)
        w.initialize(work/'initial.pem')
        (work/'nginx.conf').write_text(f'pid {work}/nginx.pid; error_log {work}/nginx.log; events {{}} http {{ access_log off; server {{ listen 127.0.0.1:19443 ssl; server_name localhost; include {work}/store/active.conf; location = /health {{ return 200 "ok"; }} }} }}')
        run(['/usr/sbin/nginx','-c',work/'nginx.conf'])
        case('baseline_fresh_tls',lambda:w.confirm(w.status()['committed'],time.monotonic()+4))
        def token_attempt():
            try:run([step,'ca','renew','--mtls=false','--force','--out',work/'token.pem','--ca-url','https://localhost:19090','--root',root,work/'initial.pem',work/'initial.key'],15)
            except subprocess.CalledProcessError as e:
                log=(work/'ca.log').read_text()
                assert 'incompatible key usage' in log
                assert e.returncode==1
                eku=run(['openssl','x509','-in',work/'initial.pem','-ext','extendedKeyUsage','-noout']).decode()
                assert 'TLS Web Server Authentication' in eku and 'TLS Web Client Authentication' not in eku
                return {'returncode':e.returncode,'ca_reason':'incompatible key usage','leaf_eku':'serverAuth only'}
            raise AssertionError('compatibility result changed; revisit contract')
        case('server_only_token_renewal_incompatibility_observed',token_attempt)
        case('real_ca_same_key_reissuance',lambda:reissue(step,'https://localhost:19090',root,work/'initial.key',work/'password',work/'new.pem'))
        case('candidate_validation',lambda:validate(work/'new.pem',work/'initial.key',root,'localhost'))
        case('wrong_san_rejected',lambda:reject(lambda:validate(work/'new.pem',work/'initial.key',root,'wrong.invalid')))
        run(['openssl','ecparam','-name','prime256v1','-genkey','-noout','-out',work/'wrong.key'])
        case('wrong_key_rejected',lambda:reject(lambda:validate(work/'new.pem',work/'wrong.key',root,'localhost')))
        def truncated_wire():
            listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen(1)
            context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(str(work/'initial.pem'),str(work/'initial.key'))
            errors=[]
            def serve():
                try:
                    raw,_=listener.accept()
                    with context.wrap_socket(raw,server_side=True) as tls:
                        tls.recv(4096);tls.sendall(b'HTTP/1.1 200 OK\r\n')
                except Exception as e:errors.append(type(e).__name__)
                finally:listener.close()
            thread=threading.Thread(target=serve,daemon=True);thread.start()
            result=reject(lambda:probe('127.0.0.1',listener.getsockname()[1],'localhost',root,fingerprint(work/'initial.pem')))
            thread.join(4);assert not thread.is_alive() and not errors
            return result
        case('real_tls_truncated_http_rejected',truncated_wire)
        def dual_eku():
            cert=work/'dual.pem'
            run(['openssl','req','-new','-x509','-key',work/'initial.key','-subj','/CN=localhost','-sha256',
                 '-addext','subjectAltName=DNS:localhost','-addext','basicConstraints=critical,CA:FALSE',
                 '-addext','extendedKeyUsage=serverAuth,clientAuth','-out',cert])
            try:validate(cert,work/'initial.key',cert,'localhost')
            except Rejected as e:assert str(e)=='eku_policy';return 'dual EKU specifically rejected'
            raise AssertionError('dual EKU accepted')
        case('dual_eku_policy_rejected',dual_eku)
        s=w.status();oldfp=fingerprint(work/'initial.pem')
        case('real_activation_new_tls',lambda:w.activate(work/'new.pem',s['epoch'],s['revision'])['state'])
        case('old_authority_rejected',lambda:reject(lambda:w.activate(work/'new.pem',s['epoch'],s['revision'])))
        case('old_fingerprint_rejected',lambda:reject(lambda:probe('127.0.0.1',19443,'localhost',root,oldfp)))
        # Simulate reload omission through a real alternate config that selects the committed version.
        def no_effect():
            before=w.status()
            def failpoint(point):
                if point=='selected':raise Rejected('injected_after_select')
            reject(lambda:w.activate(work/'initial.pem',before['epoch'],before['revision'],failpoint))
            assert w.status()['committed']==before['committed']
            return w.confirm(before['committed'],time.monotonic()+3)
        case('selected_failure_verified_rollback',no_effect)
        def crashes():
            for point in ['intent','selected','reload','confirmed']:
                s=w.status();cr,cw=os.pipe();pid=os.fork()
                if pid==0:
                    def stop(p):
                        if p==point:
                            os.write(cw,p.encode());os.kill(os.getpid(),signal.SIGKILL)
                    w.activate(work/'initial.pem',s['epoch'],s['revision'],stop);os._exit(9)
                os.close(cw)
                reached=os.read(cr,64).decode();os.close(cr)
                _,status=os.waitpid(pid,0)
                assert reached==point and os.WIFSIGNALED(status) and os.WTERMSIG(status)==signal.SIGKILL
                assert w.status()['state']=='APPLYING'
                recovered=w.recover();assert recovered['committed']==s['committed'];assert recovered['epoch']!=s['epoch']
            return 'SIGKILL at four boundaries; prior committed fingerprint re-observed'
        case('process_crash_recovery',crashes)
        def held():
            r,wr=os.pipe();pid=os.fork()
            if pid==0:
                os.close(r)
                with w.locked() as (_,lock):os.write(wr,b'x');time.sleep(2)
                os._exit(0)
            os.close(wr);os.read(r,1);os.close(r)
            try:result=reject(w.recover)
            finally:os.waitpid(pid,0)
            return result
        case('delayed_executor_blocks_takeover',held)
        def full():
            with w.locked() as (db,_):
                pages=db.execute('PRAGMA page_count').fetchone()[0]
                db.execute('PRAGMA max_page_count='+str(pages))
                before=w.read(db)
                try:w.save(db,{**before,'padding':'x'*1000000})
                except Exception as e:
                    assert getattr(e,'sqlite_errorname',None)=='SQLITE_FULL';db.rollback()
                else:raise AssertionError('not FULL')
                assert w.read(db)==before
            return 'real SQLite max_page_count FULL; existing transaction retained'
        case('sqlite_full_no_false_commit',full)
        def stopped_master():
            before=w.status();master=int((work/'nginx.pid').read_text())
            os.kill(master,signal.SIGSTOP)
            try:
                reject(lambda:w.activate(work/'initial.pem',before['epoch'],before['revision']))
                assert w.status()['state']=='READY'
                assert w.status()['committed']==before['committed']
            finally:os.kill(master,signal.SIGCONT)
            assert w.recover()['committed']==before['committed']
            return 'real master SIGSTOP: reload signal is insufficient; candidate confirmation times out; old workers still serve committed certificate; verified rollback and repair pass'
        case('reload_signal_without_application_not_success',stopped_master)
        def pending_commit():
            before=w.status();original=w.save;injected=[False]
            def save(db,state):
                if state['state']=='READY' and state['committed']!=before['committed'] and not injected[0]:
                    injected[0]=True
                    db.execute('INSERT OR REPLACE INTO state VALUES(1,?)',(json.dumps(state),))
                    raise __import__('sqlite3').OperationalError('injected commit failure with open transaction')
                return original(db,state)
            with patch.object(w,'save',save):
                try:w.activate(work/'initial.pem',before['epoch'],before['revision'])
                except __import__('sqlite3').OperationalError:pass
                else:raise AssertionError('commit failure accepted')
            assert injected[0] and w.status()['committed']==before['committed']
            return w.confirm(before['committed'],time.monotonic()+3)
        case('injected_open_transaction_commit_failure',pending_commit)
        def readonly():
            before=w.status();store=str(w.root)
            run(['mount','--bind',store,store])
            try:
                run(['mount','-o','remount,bind,ro',store])
                try:w.activate(work/'initial.pem',before['epoch'],before['revision'])
                except OSError as e:assert e.errno==30
                except Exception as e:
                    assert getattr(e,'sqlite_errorname','') in {'SQLITE_READONLY','SQLITE_READONLY_DBMOVED'}
                else:raise AssertionError('read-only accepted')
                probe('127.0.0.1',19443,'localhost',root,w.check(before['committed']))
            finally:run(['umount',store])
            assert w.status()==before
            return w.recover()['state']
        case('real_readonly_mount_rejection_and_repair',readonly)
        report['passed']=True
    except Exception as e:
        report['error']=type(e).__name__;traceback.print_exc()
    finally:
        if (work/'nginx.pid').exists():
            try:
                master=int((work/'nginx.pid').read_text())
                children=run(['pgrep','-P',str(master)]).decode().split()
                run(['/usr/sbin/nginx','-s','quit','-c',work/'nginx.conf'])
                end=time.monotonic()+5
                while time.monotonic()<end:
                    alive=[]
                    for pid in [str(master)]+children:
                        stat=pathlib.Path('/proc')/pid/'stat'
                        if stat.exists() and stat.read_text().split()[2]!='Z':alive.append(pid)
                    if not alive:break
                    time.sleep(.05)
                else:raise RuntimeError('nginx cleanup timeout')
                report['nginx_process_cleanup']=True
            except Exception:report['cleanup_error']='nginx'
        if ca:
            ca.terminate()
            try:ca.wait(timeout=5)
            except subprocess.TimeoutExpired:ca.kill();ca.wait()
        report['passed']=report['passed'] and not report.get('cleanup_error')
        report['elapsed_seconds']=time.monotonic()-start
        report['controller_maxrss_kib']=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        report['private_fixture_bytes']=sum(f.stat().st_size for f in work.rglob('*') if f.is_file())
        def version(command):
            try:return run(command).decode().splitlines()[0]
            except Exception:return 'unavailable'
        report['versions']={'nginx':subprocess.run(['/usr/sbin/nginx','-v'],capture_output=True).stderr.decode().strip(),'step':version([step,'version']),'step_ca':version([stepca,'version']),'python':platform.python_version(),'openssl':version(['openssl','version'])}
        report['source_sha256']=START_HASHES
        report['source_unchanged']=source_hashes()==START_HASHES
        report['passed']=report['passed'] and report['source_unchanged']
        (P/'evidence').mkdir(exist_ok=True)
        data=json.dumps(report,indent=2)
        out=P/'evidence/exploration.json'
        out.write_text(data);(P/'evidence/exploration.html').write_text('<!doctype html><meta charset="utf-8"><title>Certweft evidence</title><pre>'+html.escape(data)+'</pre>')
        print(json.dumps({'passed':report['passed'],'cases':len(report['cases']),'error':report.get('error')}))
        # Keep private fixture in VM for diagnosis; never copy keys or logs to source.
    return 0 if report['passed'] and not report.get('cleanup_error') else 1
if __name__=='__main__':sys.exit(main())
