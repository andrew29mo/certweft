"""Real service request replay/cancellation/commit ordering in isolated Linux VM."""
import os,sys,json,pathlib,tempfile,subprocess,time,signal,sqlite3,ssl,socket,hashlib,html,shutil
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
from certweft.core import Writer,run,fingerprint
from certweft import deadlines
from tools.executor_vm import request,hashes
P=pathlib.Path(__file__).resolve().parents[1]
def main():
    os.umask(0o077);source=hashes();out=P/'evidence/deadlines.json';out.parent.mkdir(exist_ok=True)
    if out.exists():
        archive=P/'evidence/deadline-attempts';archive.mkdir(exist_ok=True);shutil.copyfile(out,archive/(str(time.time_ns())+'.json'))
    def publish(d):
        text=json.dumps(d,indent=2);out.with_suffix('.html').write_text('<!doctype html><meta charset="utf-8"><pre>'+html.escape(text)+'</pre>');out.write_text(text)
    publish({'passed':False,'status':'in_progress'})
    work=pathlib.Path(tempfile.mkdtemp(prefix='cw-deadline-',dir='/var/tmp'));os.chmod(work,0o711)
    report={'passed':False,'cases':[],'untested':['persistent systemd deployment','VM reboot','power loss','CA signing deadline','actual VM boot change','actual wall-clock jump','physical storage faults','automatic history recycling']};servers=[];children=[];ngpid=None
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
        conf=work/'nginx.conf';w=Writer(work/'store','/usr/sbin/nginx',conf,trust,key,'localhost','127.0.0.1',19446);w.initialize(old)
        conf.write_text(f'pid {work}/nginx.pid; error_log {work}/nginx.log; events {{}} http {{ access_log off; server {{ listen 127.0.0.1:19446 ssl; server_name localhost; include {work}/store/active.conf; location = /health {{ return 200 "ok"; }} }} }}')
        run(['/usr/sbin/nginx','-c',conf]);ngpid=int((work/'nginx.pid').read_text());raw=pathlib.Path('/proc',str(ngpid),'stat').read_text()
        config={'writer':{'root':str(w.root),'nginx':w.nginx,'conf':str(conf),'ca':str(trust),'key':str(key),'host':'localhost','ip':'127.0.0.1','port':19446},'controller_uid':uid,'socket':str(work/'writer.sock'),'lease':str(work/'lifetime.lock'),'master':{'pid':ngpid,'start':raw[raw.rfind(')')+2:].split()[19]}}
        def start(pause=False,fail_dispatch=False,pause_at='confirmed',delay_at=None,delay_seconds=0):
            cfg={**config,'executor_inventory':str(work/'executors.jsonl'),'fail_dispatch':fail_dispatch}
            if delay_at:cfg.update(delay_at=delay_at,delay_seconds=delay_seconds)
            if pause:
                (work/'marker.json').unlink(missing_ok=True);cfg.update(pause_at=pause_at,marker=str(work/'marker.json'))
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
            (work/'marker.json').unlink(missing_ok=True)
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
            with socket.create_connection(('127.0.0.1',19446),2) as raw:
                with ctx.wrap_socket(raw,server_hostname='localhost') as tls:
                    assert not tls.session_reused and hashlib.sha256(tls.getpeercert(True)).hexdigest()==fingerprint(cert)
                    tls.sendall(b'GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n');assert tls.recv(1024).startswith(b'HTTP/1.1 200 ')
        def until(record):
            left=(record['expires_boot_ns']-deadlines.now_ns())/1e9
            if left>0:time.sleep(left+.05)
        parent=start(True);job={**body('expiry-after-confirm',new),'timeout_seconds':2}
        assert call(job)['created'];pid=paused();original=call({'op':'request-status','request_id':job['request_id']})['result']['timing']
        def replay():
            duplicate=call(job);assert not duplicate['created'] and duplicate['result']['timing']==original
            conflict=call({**job,'timeout_seconds':3});assert not conflict['ok'] and conflict['reason']=='request_conflict'
            return 'same timing returned; timeout extension under same ID rejected'
        case('replay_does_not_extend_budget',replay)
        def after_confirm():
            until(original['activation']);os.kill(pid,signal.SIGCONT)
            result=poll(job['request_id']);assert result['state']=='ROLLED_BACK' and result['result']['expired'];wire(old)
            timing=result['timing'];assert timing['activation']==original['activation']
            assert timing['recovery']['seconds']==5 and timing['recovery']['accepted_boot_ns']>=timing['activation']['expires_boot_ns']
            return 'expired after fresh candidate TLS; COMMIT denied; independent persisted recovery budget restores baseline'
        case('expiry_after_confirmation_rollback',after_confirm)
        parent.terminate();parent.wait(3);parent=start(True,pause_at='intent')
        job={**body('expiry-before-publication',new),'timeout_seconds':1};baseline=os.readlink(w.root/'active.conf')
        def before_publish():
            assert call(job)['created'];pid=paused();timing=call({'op':'request-status','request_id':job['request_id']})['result']['timing']
            assert os.readlink(w.root/'active.conf')==baseline;wire(old)
            until(timing['activation']);os.kill(pid,signal.SIGCONT)
            result=poll(job['request_id']);assert result['state']=='ROLLED_BACK' and result['result']['expired'];wire(old)
            return 'intent persisted but selected pointer unchanged at expiry; no candidate COMMIT'
        case('expiry_before_publication',before_publish)
        parent.terminate();parent.wait(3);parent=start(True,pause_at='preparing')
        job={**body('preparation-delay',new),'timeout_seconds':1};before=w.status()
        def preparation():
            assert call(job)['created'];pid=paused();timing=call({'op':'request-status','request_id':job['request_id']})['result']['timing']
            until(timing['activation']);os.kill(pid,signal.SIGCONT)
            result=poll(job['request_id']);assert result['state']=='EXPIRED' and result['timing']['recovery'] is None
            assert w.status()==before;wire(old)
            return 'SIGSTOP preparation delay consumes admission budget; no publication or fresh recovery allocation'
        case('preparation_consumes_overall_budget',preparation)
        parent.terminate();parent.wait(3);parent=start(True)
        job={**body('restart-before-expiry',new),'timeout_seconds':10}
        def restart(expired):
            assert call(job)['created'];pid=paused();original=call({'op':'request-status','request_id':job['request_id']})['result']['timing']
            os.kill(parent.pid,signal.SIGKILL);parent.wait(3)
            with sqlite3.connect('file:'+str(w.root/'journal.db')+'?mode=ro',uri=True) as db:
                assert json.loads(db.execute('SELECT data FROM state').fetchone()[0])['state']=='APPLYING'
            os.kill(pid,signal.SIGKILL)
            for _ in range(100):
                path=pathlib.Path('/proc',str(pid),'stat')
                if not path.exists() or path.read_text().split()[2]=='Z':break
                time.sleep(.02)
            if expired:until(original['activation'])
            start();result=poll(job['request_id']);assert result['state']=='INTERRUPTED'
            assert result['timing']['activation']==original['activation'];assert result['timing']['recovery']['seconds']==5
            duplicate=call(job);assert not duplicate['created'] and duplicate['result']['timing']==result['timing'];wire(old)
            return 'pending journal recovered without replay; activation timing identical; expired='+str(expired)
        case('restart_before_expiry_no_reset',lambda:restart(False))
        servers[-1].terminate();servers[-1].wait(3);parent=start(True)
        job={**body('restart-after-expiry',new),'timeout_seconds':1}
        case('restart_after_expiry_no_reset',lambda:restart(True))
        servers[-1].terminate();servers[-1].wait(3)
        parent=start(True,pause_at='recovery',delay_at='confirmed',delay_seconds=1.2)
        job={**body('interrupted-recovery',new),'timeout_seconds':1}
        def recovery_restart(exhausted):
            assert call(job)['created'];pid=paused();row=call({'op':'request-status','request_id':job['request_id']})['result'];recovery=row['timing']['recovery'];assert recovery is not None
            os.kill(parent.pid,signal.SIGKILL);parent.wait(3);os.kill(pid,signal.SIGKILL)
            for _ in range(100):
                path=pathlib.Path('/proc',str(pid),'stat')
                if not path.exists() or path.read_text().split()[2]=='Z':break
                time.sleep(.02)
            if exhausted:until(recovery)
            start();result=poll(job['request_id']);assert result['timing']['recovery']==recovery
            if exhausted:
                assert result['state']=='DEGRADED' and result['result']['recovered'] is False
                assert w.status()['state']=='DEGRADED'
                blocked=call({**job,'request_id':'blocked'});assert not blocked['ok'] and blocked['reason']=='degraded'
            else:
                assert result['state']=='INTERRUPTED' and result['result']['recovered'] is True;wire(old)
            return 'persisted recovery budget unchanged across restart; exhausted='+str(exhausted)
        case('recovery_budget_reused_before_expiry',lambda:recovery_restart(False))
        servers[-1].terminate();servers[-1].wait(3)
        parent=start(True,pause_at='recovery',delay_at='confirmed',delay_seconds=1.2)
        job={**body('exhausted-recovery',new),'timeout_seconds':1}
        case('recovery_budget_not_reset_after_restart',lambda:recovery_restart(True))
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
        tracked=[]
        if (work/'executors.jsonl').exists():
            tracked=[json.loads(line) for line in (work/'executors.jsonl').read_text().splitlines()]
        report['tracked_executors']=len(tracked)
        if ngpid:
            try:
                workers=run(['pgrep','-P',str(ngpid)]).decode().split();run(['/usr/sbin/nginx','-s','quit','-c',work/'nginx.conf'])
                for _ in range(100):
                    live=[]
                    for pid in [ngpid,*map(int,workers),*children]:
                        st=pathlib.Path('/proc',str(pid),'stat')
                        if st.exists() and st.read_text().split()[2]!='Z':live.append(pid)
                    for entry in tracked:
                        path=pathlib.Path('/proc',str(entry['pid']),'stat')
                        if path.exists():
                            raw=path.read_text();fields=raw[raw.rfind(')')+2:].split()
                            if fields[19]==entry['start'] and fields[0]!='Z':live.append(entry['pid'])
                    if not live:break
                    time.sleep(.03)
                else:raise AssertionError('cleanup')
                report['owned_processes_exited']=True
            except Exception:report['cleanup_error']='nginx'
        report['source_sha256']=source;report['source_unchanged']=source==hashes();report['passed']=report['passed'] and report['source_unchanged'] and not report.get('cleanup_error')
        publish(report);print(json.dumps({'passed':report['passed'],'cases':len(report['cases']),'error':report.get('error')}))
    return 0 if report['passed'] else 1
if __name__=='__main__':sys.exit(main())
