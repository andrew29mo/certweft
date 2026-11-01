"""Real service request replay/cancellation/commit ordering in isolated Linux VM."""
import os,sys,json,pathlib,tempfile,subprocess,time,signal,sqlite3,ssl,socket,hashlib,html,shutil
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
from certweft.core import Writer,run,fingerprint
from tools.executor_vm import request,hashes
P=pathlib.Path(__file__).resolve().parents[1]
def main():
    os.umask(0o077);source=hashes();out=P/'evidence/operations.json';out.parent.mkdir(exist_ok=True)
    if out.exists():
        archive=P/'evidence/operations-attempts';archive.mkdir(exist_ok=True);shutil.copyfile(out,archive/(str(time.time_ns())+'.json'))
    def publish(d):
        text=json.dumps(d,indent=2);out.with_suffix('.html').write_text('<!doctype html><meta charset="utf-8"><pre>'+html.escape(text)+'</pre>');out.write_text(text)
    publish({'passed':False,'status':'in_progress'})
    work=pathlib.Path(tempfile.mkdtemp(prefix='cw-operations-',dir='/var/tmp'));os.chmod(work,0o711)
    report={'passed':False,'cases':[],'untested':['persistent systemd deployment','VM reboot','power loss','durable whole-operation deadlines','physical storage faults','automatic history recycling']};servers=[];children=[];ngpid=None
    def case(name,fn):
        t=time.monotonic()
        try:detail=fn()
        except Exception as e:report['cases'].append({'name':name,'passed':False,'error':type(e).__name__});raise
        report['cases'].append({'name':name,'passed':True,'seconds':time.monotonic()-t,'detail':detail})
    try:
        import pwd
        uid=pwd.getpwnam('nobody').pw_uid;key=work/'key';ca_key=work/'ca-key';trust=work/'root.pem';old=work/'old.pem';new=work/'new.pem';csr=work/'req';ext=work/'ext'
        for k in [key,ca_key]:run(['openssl','ecparam','-name','prime256v1','-genkey','-noout','-out',k])
        run(['openssl','req','-new','-x509','-key',ca_key,'-subj','/CN=Operations Fixture','-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=keyCertSign,cRLSign','-out',trust])
        run(['openssl','req','-new','-key',key,'-subj','/CN=localhost','-out',csr])
        ext.write_text('subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\nbasicConstraints=critical,CA:FALSE\n')
        for cert,serial in [(old,'1'),(new,'2')]:run(['openssl','x509','-req','-in',csr,'-CA',trust,'-CAkey',ca_key,'-sha256','-set_serial',serial,'-days','1','-extfile',ext,'-out',cert])
        conf=work/'nginx.conf';w=Writer(work/'store','/usr/sbin/nginx',conf,trust,key,'localhost','127.0.0.1',19445);w.initialize(old)
        conf.write_text(f'pid {work}/nginx.pid; error_log {work}/nginx.log; events {{}} http {{ access_log off; server {{ listen 127.0.0.1:19445 ssl; server_name localhost; include {work}/store/active.conf; location = /health {{ return 200 "ok"; }} }} }}')
        run(['/usr/sbin/nginx','-c',conf]);ngpid=int((work/'nginx.pid').read_text());raw=pathlib.Path('/proc',str(ngpid),'stat').read_text()
        config={'writer':{'root':str(w.root),'nginx':w.nginx,'conf':str(conf),'ca':str(trust),'key':str(key),'host':'localhost','ip':'127.0.0.1','port':19445},'controller_uid':uid,'socket':str(work/'writer.sock'),'lease':str(work/'lifetime.lock'),'master':{'pid':ngpid,'start':raw[raw.rfind(')')+2:].split()[19]}}
        def start(pause=False):
            cfg={**config}
            if pause:
                (work/'marker.json').unlink(missing_ok=True);cfg.update(pause_at='confirmed',marker=str(work/'marker.json'))
            path=work/('config-'+str(len(servers)));path.write_text(json.dumps(cfg))
            proc=subprocess.Popen([sys.executable,'-m','certweft.service',str(path)],cwd=P,stdout=open(work/('service-'+str(len(servers))+'.log'),'wb'),stderr=subprocess.STDOUT);servers.append(proc)
            for _ in range(150):
                if proc.poll() is not None:raise AssertionError('startup_failed')
                try:
                    if request(config['socket'],{'op':'status'})['ok']:return proc
                except (OSError,EOFError):pass
                time.sleep(.03)
            raise AssertionError('startup_timeout')
        def call(body):
            code='import json,sys;from tools.executor_vm import request;print(json.dumps(request(sys.argv[1],json.loads(sys.argv[2]))))'
            return json.loads(run(['runuser','-u','nobody','--',sys.executable,'-c',code,config['socket'],json.dumps(body)]))
        def body(identity,cert):
            s=w.status();return {'op':'submit','request_id':identity,'certificate':cert.read_text(),'epoch':s['epoch'],'revision':s['revision']}
        def paused():
            for _ in range(100):
                if (work/'marker.json').exists():
                    pid=json.loads((work/'marker.json').read_text())['pid'];children.append(pid);return pid
                time.sleep(.02)
            raise AssertionError('checkpoint_missing')
        def poll(identity):
            for _ in range(150):
                result=call({'op':'request-status','request_id':identity});assert result['ok']
                if result['result']['state'] not in {'ACCEPTED','RUNNING','CANCEL_REQUESTED'}:return result['result']
                time.sleep(.03)
            raise AssertionError('operation_stuck')
        def wire(cert):
            ctx=ssl.create_default_context(cafile=str(trust))
            with socket.create_connection(('127.0.0.1',19445),2) as raw:
                with ctx.wrap_socket(raw,server_hostname='localhost') as tls:
                    assert not tls.session_reused and hashlib.sha256(tls.getpeercert(True)).hexdigest()==fingerprint(cert)
                    tls.sendall(b'GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n');assert tls.recv(1024).startswith(b'HTTP/1.1 200 ')
        parent=start(True);a=body('cancel-first',new)
        def replay():
            assert call(a)['created'];pid=paused();before=len(list(w.root.glob('v-*')))
            duplicate=call(a);assert duplicate['ok'] and not duplicate['created']
            conflict=call({**a,'certificate':old.read_text()});assert not conflict['ok'] and conflict['reason']=='request_conflict'
            assert len(list(w.root.glob('v-*')))==before
            return 'duplicate while executing returns same durable request; different parameters rejected without new generation'
        case('inflight_replay_and_conflict',replay)
        def cancel_wins():
            response=call({'op':'cancel','request_id':a['request_id']});assert response['ok'] and response['result']['state']=='CANCEL_REQUESTED' and response['cancel_accepted'] and not response['cancel_complete']
            os.kill(children[-1],signal.SIGCONT);result=poll(a['request_id']);assert result['state']=='ROLLED_BACK';wire(old)
            return 'cancel persisted after new wire confirmation, before COMMIT; rollback independently observed'
        case('cancel_before_commit_wins',cancel_wins)
        parent.terminate();parent.wait(3);parent=start()
        def terminal_replay():
            before=len(list(w.root.glob('v-*')));response=call(a)
            assert response['ok'] and not response['created'] and response['result']['state']=='ROLLED_BACK'
            assert len(list(w.root.glob('v-*')))==before
            return 'restart preserves terminal result; old request not rerun'
        case('restart_terminal_no_replay',terminal_replay)
        b=body('commit-first',new)
        def commit_wins():
            assert call(b)['created'];assert poll(b['request_id'])['state']=='COMMITTED';wire(new)
            response=call({'op':'cancel','request_id':b['request_id']});assert response['result']['state']=='COMMITTED' and not response['cancel_accepted'] and not response['cancel_complete']
            parent.terminate();parent.wait(3)
            start();before=len(list(w.root.glob('v-*')))
            assert not call(b)['created'] and poll(b['request_id'])['state']=='COMMITTED'
            assert len(list(w.root.glob('v-*')))==before;wire(new)
            return 'COMMIT atomically wins; later cancel reports COMMITTED; restart replay does not execute'
        case('commit_before_cancel_wins',commit_wins)
        servers[-1].terminate();servers[-1].wait(3);parent=start(True);c=body('interrupted',old)
        def interruption():
            assert call(c)['created'];pid=paused();os.kill(parent.pid,signal.SIGKILL);parent.wait(3)
            with sqlite3.connect('file:'+str(w.root/'journal.db')+'?mode=ro',uri=True) as db:
                assert json.loads(db.execute('SELECT data FROM state').fetchone()[0])['state']=='APPLYING'
                assert db.execute('SELECT state FROM requests WHERE id=?',(c['request_id'],)).fetchone()[0]=='RUNNING'
            os.kill(pid,signal.SIGKILL)
            for _ in range(100):
                st=pathlib.Path('/proc',str(pid),'stat')
                if not st.exists() or st.read_text().split()[2]=='Z':break
                time.sleep(.03)
            start();result=poll(c['request_id']);assert result['state']=='INTERRUPTED'
            assert not call(c)['created'];wire(new)
            return 'SIGKILL preserves pending journal; startup recovers baseline and marks INTERRUPTED without replay'
        case('pending_restart_no_replay',interruption)
        servers[-1].terminate();servers[-1].wait(3);parent=start(True);d=body('cancel-write-failure',old)
        def write_failure():
            assert call(d)['created'];pid=paused()
            with sqlite3.connect(w.root/'journal.db') as db:db.execute("CREATE TRIGGER reject_cancel BEFORE UPDATE ON requests WHEN NEW.state='CANCEL_REQUESTED' BEGIN SELECT RAISE(ABORT,'injected'); END")
            result=call({'op':'cancel','request_id':d['request_id']});assert not result['ok']
            assert call({'op':'request-status','request_id':d['request_id']})['result']['state']=='RUNNING'
            with sqlite3.connect(w.root/'journal.db') as db:db.execute('DROP TRIGGER reject_cancel')
            assert call({'op':'cancel','request_id':d['request_id']})['result']['state']=='CANCEL_REQUESTED'
            os.kill(pid,signal.SIGCONT);assert poll(d['request_id'])['state']=='ROLLED_BACK';wire(new)
            return 'injected cancellation persistence failure returns error, not acknowledgement; repaired retry rolls back'
        case('cancel_write_failure_no_false_ack',write_failure)
        def no_implicit_repair():
            with w.locked() as (db,_):
                state=w.read(db);state['state']='DEGRADED';w.save(db,state)
            before=w.status();job={'op':'submit','request_id':'no-implicit-repair','certificate':old.read_text(),'epoch':before['epoch'],'revision':before['revision']}
            assert call(job)['created'];assert poll(job['request_id'])['state']=='DEGRADED'
            assert w.status()==before;wire(new)
            result=call({**job,'request_id':'blocked-after-degraded'})
            assert not result['ok'] and result['reason']=='degraded'
            return 'root-injected preexisting DEGRADED cannot be repaired by controller submit; new IDs refused'
        case('controller_cannot_implicitly_repair_degraded',no_implicit_repair)
        report['passed']=True
    except Exception as error:
        import traceback;traceback.print_exc();report['error']=type(error).__name__
    finally:
        for pid in children:
            try:os.kill(pid,signal.SIGKILL)
            except ProcessLookupError:pass
        for proc in servers:
            if proc.poll() is None:proc.terminate()
            try:proc.wait(3)
            except subprocess.TimeoutExpired:proc.kill();proc.wait();report['cleanup_error']='server'
        if ngpid:
            try:
                workers=run(['pgrep','-P',str(ngpid)]).decode().split();run(['/usr/sbin/nginx','-s','quit','-c',work/'nginx.conf'])
                for _ in range(100):
                    live=[]
                    for pid in [ngpid,*map(int,workers),*children]:
                        st=pathlib.Path('/proc',str(pid),'stat')
                        if st.exists() and st.read_text().split()[2]!='Z':live.append(pid)
                    if not live:break
                    time.sleep(.03)
                else:raise AssertionError('cleanup')
                report['owned_processes_exited']=True
            except Exception:report['cleanup_error']='nginx'
        report['source_sha256']=source;report['source_unchanged']=source==hashes();report['passed']=report['passed'] and report['source_unchanged'] and not report.get('cleanup_error')
        publish(report);print(json.dumps({'passed':report['passed'],'cases':len(report['cases']),'error':report.get('error')}))
    return 0 if report['passed'] else 1
if __name__=='__main__':sys.exit(main())
