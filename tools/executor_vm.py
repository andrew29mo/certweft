"""Real UDS writer, unprivileged callers, exec orphan and Nginx fencing VM cases."""
import ssl
import sqlite3
import os,sys,json,pathlib,tempfile,subprocess,socket,time,signal,hashlib,html,shutil,threading
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
from certweft.core import Writer,run,fingerprint
P=pathlib.Path(__file__).resolve().parents[1]
def hashes():
    return {str(f.relative_to(P)):hashlib.sha256(f.read_bytes()).hexdigest() for d in ['certweft','tools','tests','policy'] for f in (P/d).glob('*') if f.is_file()}
def request(endpoint,body):
    with socket.socket(socket.AF_UNIX) as s:
        s.settimeout(25);s.connect(str(endpoint));s.sendall(json.dumps(body).encode()+b'\n');out=b''
        while not out.endswith(b'\n'):
            chunk=s.recv(4096)
            if not chunk:raise EOFError('writer_closed')
            out+=chunk
        return json.loads(out)
def main():
    os.umask(0o077);source=hashes();out=P/'evidence/executor.json';out.parent.mkdir(exist_ok=True)
    if out.exists():
        archive=P/'evidence/executor-attempts';archive.mkdir(exist_ok=True);shutil.copyfile(out,archive/(str(time.time_ns())+'.json'))
    def publish(d):
        text=json.dumps(d,indent=2);out.with_suffix('.html').write_text('<!doctype html><meta charset="utf-8"><pre>'+html.escape(text)+'</pre>');out.write_text(text)
    publish({'passed':False,'status':'in_progress'})
    work=pathlib.Path(tempfile.mkdtemp(prefix='cw-executor-',dir='/var/tmp'));os.chmod(work,0o711)
    report={'passed':False,'cases':[],'untested':['persistent systemd installation','D-state processes','power loss','VM reboot recovery','request dedup and durable deadlines','root compromise']};servers=[];ngpid=None;childpid=None
    def case(name,fn):
        t=time.monotonic()
        try:detail=fn()
        except Exception as e:report['cases'].append({'name':name,'passed':False,'error':type(e).__name__});raise
        report['cases'].append({'name':name,'passed':True,'detail':detail,'seconds':time.monotonic()-t})
    def start(config,ready=True):
        f=work/('config-'+str(len(servers))+'.json');f.write_text(json.dumps(config));f.chmod(0o600)
        proc=subprocess.Popen([sys.executable,'-m','certweft.service',str(f)],cwd=P,stdout=open(work/('server-'+str(len(servers))+'.log'),'wb'),stderr=subprocess.STDOUT);proc.config_file=f;servers.append(proc)
        if ready:
            for _ in range(100):
                if proc.poll() is not None:raise AssertionError('server_failed')
                try:
                    if request(config['socket'],{'op':'status'})['ok']:break
                except OSError:time.sleep(.03)
            else:raise AssertionError('server_not_ready')
        return proc
    try:
        import pwd
        uid=pwd.getpwnam('nobody').pw_uid
        key=work/'key.pem';old=work/'old.pem';new=work/'new.pem'
        run(['openssl','ecparam','-name','prime256v1','-genkey','-noout','-out',key])
        # Dedicated OpenSSL CA fixture; not the separately qualified step-ca path.
        cakey=work/'ca.key';trust=work/'trust.pem'
        run(['openssl','ecparam','-name','prime256v1','-genkey','-noout','-out',cakey])
        run(['openssl','req','-new','-x509','-key',cakey,'-sha256','-subj','/CN=Certweft Executor Fixture',
             '-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign','-out',trust])
        csr=work/'leaf.csr';ext=work/'leaf.ext'
        run(['openssl','req','-new','-key',key,'-subj','/CN=localhost','-out',csr])
        ext.write_text('subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\nbasicConstraints=critical,CA:FALSE\nkeyUsage=digitalSignature\n')
        for cert in [old,new]:
            run(['openssl','x509','-req','-in',csr,'-CA',trust,'-CAkey',cakey,'-sha256','-set_serial','1' if cert==old else '2','-days','1','-extfile',ext,'-out',cert])
        conf=work/'nginx.conf';w=Writer(work/'store','/usr/sbin/nginx',conf,trust,key,'localhost','127.0.0.1',19444)
        w.initialize(old)
        conf.write_text(f'pid {work}/nginx.pid; error_log {work}/nginx.log; events {{}} http {{ access_log off; server {{ listen 127.0.0.1:19444 ssl; server_name localhost; include {work}/store/active.conf; location = /health {{ return 200 "ok"; }} }} }}')
        run(['/usr/sbin/nginx','-c',conf]);ngpid=int((work/'nginx.pid').read_text())
        raw=pathlib.Path('/proc',str(ngpid),'stat').read_text();master={'pid':ngpid,'start':raw[raw.rfind(')')+2:].split()[19]}
        config={'legacy_api':True,'writer':{'root':str(w.root),'nginx':w.nginx,'conf':str(conf),'ca':str(trust),'key':str(key),'host':'localhost','ip':'127.0.0.1','port':19444},'controller_uid':uid,'socket':str(work/'writer.sock'),'lease':str(work/'lifetime.lock'),'master':master}
        parent=start(config)
        def wire(expected):
            context=ssl.create_default_context(cafile=str(trust))
            with socket.create_connection(('127.0.0.1',19444),2) as raw:
                with context.wrap_socket(raw,server_hostname='localhost') as tls:
                    assert not tls.session_reused
                    actual=hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest()
                    assert actual==fingerprint(expected)
                    tls.sendall(b'GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n')
                    response=b''
                    while b'\r\n\r\n' not in response:
                        chunk=tls.recv(1024)
                        assert chunk;response+=chunk;assert len(response)<=4096
                    assert response.startswith(b'HTTP/1.1 200 ')
            return 'independent fresh wire fingerprint and HTTP verified'
        def bad_parent():
            directory=work/'writable';directory.mkdir();directory.chmod(0o777)
            file=directory/'config.json';file.write_text(json.dumps(config));file.chmod(0o600)
            result=subprocess.run([sys.executable,'-m','certweft.service',str(file)],capture_output=True)
            assert result.returncode!=0 and b'writable parent' in result.stderr
            return 'root-owned config in writable directory rejected'
        case('writable_configuration_hierarchy_rejected',bad_parent)
        def symlink_binary():
            link=work/'nginx-link';link.symlink_to('/usr/sbin/nginx')
            altered={**config,'writer':{**config['writer'],'nginx':str(link)}}
            path=work/'symlink-config.json';path.write_text(json.dumps(altered))
            result=subprocess.run([sys.executable,'-m','certweft.service',str(path)],capture_output=True)
            assert result.returncode!=0 and b'untrusted binary' in result.stderr
            return 'final executable symlink rejected before lease or execution'
        case('mutable_executable_symlink_rejected',symlink_binary)
        def snapshot():
            parent.config_file.write_text('{invalid replacement')
            result=request(config['socket'],{'op':'status'})
            assert result['ok']
            return 'child uses verified parent snapshot despite pathname replacement'
        case('configuration_snapshot_pinned',snapshot)
        def unpriv(body):
            code='import json,sys;from tools.executor_vm import request;print(json.dumps(request(sys.argv[1],json.loads(sys.argv[2]))))'
            return json.loads(run(['runuser','-u','nobody','--',sys.executable,'-c',code,config['socket'],json.dumps(body)]))
        def forbidden():
            for path in [w.root/'journal.db',w.root/'active.conf',key,conf,work/'lifetime.lock']:
                assert path.exists()
                code='import sys;\ntry: open(sys.argv[1],"ab");sys.exit(2)\nexcept PermissionError:sys.exit(0)'
                run(['runuser','-u','nobody','--',sys.executable,'-c',code,path])
            denied=subprocess.run(['runuser','-u','nobody','--','/usr/sbin/nginx','-s','reload','-c',str(conf)],capture_output=True)
            assert denied.returncode!=0
            return 'actual file writes and direct nginx reload denied'
        case('unprivileged_direct_mutation_denied',forbidden)
        case('controller_status',lambda:unpriv({'op':'status'})['result']['state'])
        def bad():
            for body in [{'op':'recover'},{'op':'activate','path':'/etc/passwd'},{'op':'shell','command':'id'}]:assert not unpriv(body)['ok']
            return 'admin recovery, injected path and arbitrary op rejected'
        case('fixed_api_rejects_escalation',bad)
        def bad_candidate():
            before=w.status()
            result=unpriv({'op':'activate','certificate':'not a certificate','epoch':before['epoch'],'revision':before['revision']})
            assert not result['ok'] and w.status()==before
            return 'invalid bytes independently rejected; durable state unchanged'
        case('root_revalidates_untrusted_candidate',bad_candidate)
        def other_peer():
            code='from tools.executor_vm import request;request(__import__("sys").argv[1],{"op":"status"})'
            result=subprocess.run(['runuser','-u','daemon','--',sys.executable,'-c',code,config['socket']],capture_output=True)
            assert result.returncode!=0 and b'PermissionError' in result.stderr
            return 'unconfigured UID cannot connect to management socket'
        case('unconfigured_peer_denied',other_peer)
        def activation():
            s=w.status();reply=unpriv({'op':'activate','certificate':new.read_text(),'epoch':s['epoch'],'revision':s['revision']})
            assert reply['ok'],reply;assert w.check(w.status()['committed'])==fingerprint(new);wire(new)
            return 'unprivileged certificate bytes revalidated by root executor; fresh TLS confirms new generation'
        case('formal_controller_activation',activation)
        # Stop parent cleanly first, then start root-configured checkpoint fixture.
        parent.terminate();parent.wait(3)
        config.update(pause_at='selected',marker=str(work/'paused.json'))
        parent=start(config);before=w.status();reply=[]
        def pending():
            try:reply.append(request(config['socket'],{'op':'activate','certificate':old.read_text(),'epoch':before['epoch'],'revision':before['revision']}))
            except (OSError,EOFError):pass
        thread=threading.Thread(target=pending,daemon=True);thread.start()
        for _ in range(100):
            if (work/'paused.json').exists():break
            time.sleep(.03)
        else:raise AssertionError('checkpoint_missing')
        childpid=json.loads((work/'paused.json').read_text())['pid']
        assert pathlib.Path('/proc',str(childpid),'status').read_text().split('State:',1)[1].lstrip().startswith('T')
        os.kill(parent.pid,signal.SIGKILL);parent.wait(3)
        def takeover_blocked():
            pointer=os.readlink(w.root/'active.conf')
            with sqlite3.connect('file:'+str(w.root/'journal.db')+'?mode=ro',uri=True) as db:
                journal=db.execute('SELECT data FROM state').fetchone()[0]
            assert json.loads(journal)['state']=='APPLYING'
            replacement=start(config,False)
            assert replacement.wait(3)==73
            assert b'lease_busy' in (work/('server-'+str(len(servers)-1)+'.log')).read_bytes()
            lease=os.stat(config['lease'])
            inherited=[os.stat(f) for f in pathlib.Path('/proc',str(childpid),'fd').iterdir() if f.exists()]
            assert any((st.st_dev,st.st_ino)==(lease.st_dev,lease.st_ino) for st in inherited)
            assert pathlib.Path('/proc',str(childpid)).exists()
            assert os.readlink(w.root/'active.conf')==pointer
            with sqlite3.connect('file:'+str(w.root/'journal.db')+'?mode=ro',uri=True) as db:
                assert db.execute('SELECT data FROM state').fetchone()[0]==journal
            return 'root exec child remains stopped with inherited lease; replacement exits without mutation'
        case('orphan_executor_prevents_takeover',takeover_blocked)
        def resume_old():
            os.kill(childpid,signal.SIGCONT)
            for _ in range(300):
                st=pathlib.Path('/proc',str(childpid),'stat')
                if not st.exists() or st.read_text().split()[2]=='Z':break
                time.sleep(.03)
            else:raise AssertionError('executor_not_exited')
            # Completing old operation is allowed while it is the sole lease owner.
            config.pop('pause_at');config.pop('marker');newparent=start(config)
            recovered=request(config['socket'],{'op':'recover'});assert recovered['ok']
            current=w.status()
            result=request(config['socket'],{'op':'activate','certificate':new.read_text(),'epoch':current['epoch'],'revision':current['revision']});assert result['ok']
            stale=request(config['socket'],{'op':'activate','certificate':old.read_text(),'epoch':before['epoch'],'revision':before['revision']});assert not stale['ok']
            wire(new);assert w.check(w.status()['committed'])==fingerprint(new)
            return 'old child exits before replacement acquires lease; recovery/new activation passes; old authority rejected'
        case('delayed_old_completion_then_fenced_new_generation',resume_old)
        def timeout_cleanup():
            servers[-1].terminate();servers[-1].wait(3)
            config.update(pause_at='selected',marker=str(work/'timeout.json'),pipe_holder=True)
            timeout_parent=start(config);before=w.status();answers=[]
            thread=threading.Thread(target=lambda:answers.append(request(config['socket'],{'op':'activate','certificate':old.read_text(),'epoch':before['epoch'],'revision':before['revision']})),daemon=True)
            thread.start()
            for _ in range(100):
                if (work/'timeout.json').exists():break
                time.sleep(.03)
            else:raise AssertionError('timeout_checkpoint_missing')
            info=json.loads((work/'timeout.json').read_text());assert info['descendants']
            thread.join(24);assert not thread.is_alive() and answers
            assert answers[0]=={'ok':False,'error':'TimeoutError'}
            for pid in [info['pid']]+info['descendants']:
                st=pathlib.Path('/proc',str(pid),'stat')
                assert not st.exists() or st.read_text().split()[2]=='Z'
            timeout_parent.terminate();timeout_parent.wait(3)
            for key in ['pause_at','marker','pipe_holder']:config.pop(key)
            replacement=start(config)
            assert request(config['socket'],{'op':'recover'})['ok']
            current=w.status()
            assert request(config['socket'],{'op':'activate','certificate':new.read_text(),'epoch':current['epoch'],'revision':current['revision']})['ok']
            stale=request(config['socket'],{'op':'activate','certificate':old.read_text(),'epoch':before['epoch'],'revision':before['revision']})
            assert not stale['ok'];wire(new)
            return 'real 20s timeout kills paused executor and pipe holder; replacement recovery/new activation succeeds; stale authority denied'
        case('timeout_group_cleanup_and_takeover',timeout_cleanup)
        report['passed']=True
    except Exception as e:
        import traceback;traceback.print_exc();report['error']=type(e).__name__
    finally:
        if childpid:
            try:os.kill(childpid,signal.SIGKILL)
            except ProcessLookupError:pass
        for proc in servers:
            if proc.poll() is None:proc.terminate()
            try:proc.wait(3)
            except subprocess.TimeoutExpired:proc.kill();proc.wait();report['cleanup_error']='server_forced'
        if ngpid:
            try:
                workers=run(['pgrep','-P',str(ngpid)]).decode().split()
                run(['/usr/sbin/nginx','-s','quit','-c',work/'nginx.conf'])
                end=time.monotonic()+5
                while time.monotonic()<end:
                    live=[]
                    for pid in [str(ngpid)]+workers+([str(childpid)] if childpid else []):
                        stat=pathlib.Path('/proc',pid,'stat')
                        if stat.exists() and stat.read_text().split()[2]!='Z':live.append(pid)
                    if not live:break
                    time.sleep(.03)
                else:raise RuntimeError('process_cleanup')
                report['owned_processes_exited']=True
            except Exception:report['cleanup_error']='nginx'
        report['versions']={'python':sys.version.split()[0],'nginx':subprocess.run(['/usr/sbin/nginx','-v'],capture_output=True).stderr.decode().strip(),'openssl':run(['openssl','version']).decode().strip()}
        report['source_sha256']=source;report['source_unchanged']=source==hashes();report['passed']=report['passed'] and report['source_unchanged'] and not report.get('cleanup_error')
        publish(report);print(json.dumps({'passed':report['passed'],'cases':len(report['cases']),'error':report.get('error')}))
    return 0 if report['passed'] else 1
if __name__=='__main__':sys.exit(main())
