"""Bounded real-service storage faults on a dedicated ext4 loop mount in Linux VM.

Run as root only. Never fills/remounts the host root filesystem. Root-only SQL
allocation triggers force actual SQLITE_FULL under pager quota, not RAISE().
"""
import contextlib,errno,hashlib,html,json,os,pathlib,pwd,shutil,signal,socket,sqlite3,ssl,subprocess,sys,tempfile,time
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
from certweft.core import Writer,run,fingerprint
from certweft.operations import Operations
from tools.executor_vm import hashes
P=pathlib.Path(__file__).resolve().parents[1]

def alive(pid,start=None):
    try:
        raw=pathlib.Path('/proc',str(pid),'stat').read_text();fields=raw[raw.rfind(')')+2:].split()
        return fields[0]!='Z' and (start is None or fields[19]==start)
    except FileNotFoundError:return False

def call(endpoint,body):
    # Exercise the real socket from the configured unprivileged controller UID.
    code='import json,sys;from tools.executor_vm import request;print(json.dumps(request(sys.argv[1],json.loads(sys.argv[2]))))'
    result=subprocess.run(['runuser','-u','nobody','--',sys.executable,'-c',code,str(endpoint),json.dumps(body)],cwd=P,capture_output=True,timeout=4)
    if result.returncode:return {'ok':False,'transport_unavailable':True}
    return json.loads(result.stdout)

def scenario(kind,phase):
    work=pathlib.Path(tempfile.mkdtemp(prefix='cw-storage-',dir='/var/tmp'));os.chmod(work,0o711)
    image=work/'disk.img';mount=work/'store';mount.mkdir(mode=0o700)
    parent=None;ngpid=None;ngworkers=[];mounted=False;bound=False;child=None;loop=None
    result={'fault':kind,'phase':phase,'ext4_image_bytes':32*1024*1024};t=time.monotonic()
    try:
        with image.open('wb') as f:f.truncate(32*1024*1024)
        run(['mkfs.ext4','-q','-F','-m','0',image]);run(['mount','-o','loop',image,mount]);mounted=True;os.chmod(mount,0o700)
        loop=run(['findmnt','-n','-o','SOURCE','--target',mount]).decode().strip()
        key=work/'key';cakey=work/'ca-key';ca=work/'ca.pem';old=work/'old.pem';new=work/'new.pem';csr=work/'req';ext=work/'ext'
        for k in [key,cakey]:run(['openssl','ecparam','-name','prime256v1','-genkey','-noout','-out',k])
        run(['openssl','req','-new','-x509','-key',cakey,'-subj','/CN=Storage Fixture','-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=keyCertSign,cRLSign','-out',ca])
        run(['openssl','req','-new','-key',key,'-subj','/CN=localhost','-out',csr])
        ext.write_text('subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\nbasicConstraints=critical,CA:FALSE\n')
        for cert,serial in [(old,'1'),(new,'2')]:run(['openssl','x509','-req','-in',csr,'-CA',ca,'-CAkey',cakey,'-sha256','-set_serial',serial,'-days','1','-extfile',ext,'-out',cert])
        with socket.socket() as s:s.bind(('127.0.0.1',0));port=s.getsockname()[1]
        conf=work/'nginx.conf';w=Writer(mount,'/usr/sbin/nginx',conf,ca,key,'localhost','127.0.0.1',port);w.initialize(old);Operations(mount).initialize()
        baseline=w.status();pointer=os.readlink(mount/'active.conf')
        conf.write_text(f'pid {work}/nginx.pid; error_log {work}/nginx.log; events {{}} http {{ access_log off; server {{ listen 127.0.0.1:{port} ssl; server_name localhost; include {mount}/active.conf; location = /health {{ return 200 "ok"; }} }} }}')
        run(['/usr/sbin/nginx','-c',conf]);ngpid=int((work/'nginx.pid').read_text());raw=pathlib.Path('/proc',str(ngpid),'stat').read_text()
        config={'writer':{'root':str(mount),'nginx':'/usr/sbin/nginx','conf':str(conf),'ca':str(ca),'key':str(key),'host':'localhost','ip':'127.0.0.1','port':port},'controller_uid':pwd.getpwnam('nobody').pw_uid,'socket':str(work/'writer.sock'),'lease':str(work/'lifetime.lock'),'master':{'pid':ngpid,'start':raw[raw.rfind(')')+2:].split()[19]},'executor_inventory':str(work/'executors.jsonl')}
        if phase!='pre':config.update(pause_at='preparing' if phase=='prepare' else 'confirmed',marker=str(work/'marker.json'))
        if kind=='sqlite_full':
            with contextlib.closing(sqlite3.connect(mount/'journal.db')) as db, db:
                db.execute('CREATE TABLE quota_probe(data BLOB)')
                when={'pre':"BEFORE INSERT ON requests",'prepare':"BEFORE INSERT ON state WHEN json_extract(NEW.data,'$.state')='APPLYING'",'post':"BEFORE UPDATE ON requests WHEN NEW.state='COMMITTED'",'cancel':"BEFORE UPDATE ON requests WHEN NEW.state='CANCEL_REQUESTED'"}[phase]
                db.execute('CREATE TRIGGER allocate_quota '+when+' BEGIN INSERT INTO quota_probe VALUES(zeroblob(65536)); END')
                config['sqlite_max_pages']=db.execute('PRAGMA page_count').fetchone()[0]+1
            result['pager_max_pages']=config['sqlite_max_pages'];result['allocation_bytes']=65536
        cfg=work/'config';cfg.write_text(json.dumps(config))
        log=(work/'service.log').open('wb')
        parent=subprocess.Popen([sys.executable,'-m','certweft.service',str(cfg)],cwd=P,stdout=log,stderr=subprocess.STDOUT);log.close()
        for _ in range(120):
            if parent.poll() is not None:raise AssertionError('service_startup')
            if (work/'writer.sock').exists():break
            time.sleep(.025)
        else:raise AssertionError('no_socket')
        job={'op':'submit','request_id':'storage-'+kind+'-'+phase,'certificate':new.read_text(),'epoch':baseline['epoch'],'revision':baseline['revision']}
        def wire():
            ctx=ssl.create_default_context(cafile=str(ca))
            with socket.create_connection(('127.0.0.1',port),2) as raw:
                with ctx.wrap_socket(raw,server_hostname='localhost') as tls:
                    assert not tls.session_reused
                    digest=hashlib.sha256(tls.getpeercert(True)).hexdigest()
                    tls.sendall(b'GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n');assert tls.recv(1024).startswith(b'HTTP/1.1 200 ')
            if digest==fingerprint(old):return 'baseline'
            if digest==fingerprint(new):return 'candidate'
            raise AssertionError('unexpected_wire_leaf')
        assert wire()=='baseline'
        def fault():
            nonlocal bound
            if kind=='readonly':
                run(['mount','--bind',mount,mount]);bound=True
                run(['mount','-o','remount,bind,ro',mount])
            elif kind=='enospc':
                filled=0
                with (mount/'filler').open('wb',buffering=0) as f:
                    try:
                        while True:filled+=f.write(b'x'*65536)
                    except OSError as e:assert e.errno==errno.ENOSPC
                    os.fsync(f.fileno())
                # Consume trailing partial blocks too, until even 1 byte fails.
                try:
                    with (mount/'last-blocks').open('wb',buffering=0) as f:
                        while True:f.write(b'x'*4096)
                except OSError as e:assert e.errno==errno.ENOSPC
                result['filled_bytes']=filled
            if kind!='sqlite_full':
                try:
                    with (mount/'fault-probe').open('wb',buffering=0) as f:f.write(b'x'*4096);os.fsync(f.fileno())
                except OSError as e:
                    assert e.errno=={'enospc':errno.ENOSPC,'readonly':errno.EROFS}[kind];result['observed_errno']=e.errno
                else:raise AssertionError('fault_not_real')
                result['mount_options']=run(['findmnt','-n','-o','OPTIONS','--target',mount]).decode().strip()
        def memory(pid):
            return {line.split(':')[0]:line.split(':')[1].strip() for line in pathlib.Path('/proc',str(pid),'status').read_text().splitlines() if line.startswith(('VmRSS:','VmHWM:'))}
        result['service_memory_before_fault']=memory(parent.pid)
        if phase=='pre':
            fault();reply=call(config['socket'],job);result['initial_reply']=reply
            assert not reply.get('ok') and not reply.get('created')
            assert os.readlink(mount/'active.conf')==pointer and wire()=='baseline'
        else:
            accepted=call(config['socket'],job);assert accepted.get('ok') and accepted.get('created')
            for _ in range(150):
                if (work/'marker.json').exists():child=json.loads((work/'marker.json').read_text())['pid'];break
                time.sleep(.02)
            else:raise AssertionError('confirmed_checkpoint_missing')
            if phase=='prepare':
                assert wire()=='baseline' and os.readlink(mount/'active.conf')==pointer
                result['baseline_observed_before_fault']=True
            else:
                assert wire()=='candidate';result['candidate_observed_before_fault']=True
            result['executor_memory_at_checkpoint']=memory(child)
            fault()
            if phase=='cancel':
                reply=call(config['socket'],{'op':'cancel','request_id':job['request_id']});result['cancel_reply']=reply
                assert not reply.get('ok') and not reply.get('cancel_accepted') and not reply.get('cancel_complete')
            os.kill(child,signal.SIGCONT)
            for _ in range(300):
                if not alive(child):break
                time.sleep(.025)
            else:raise AssertionError('executor_stuck')
        # New identity must be rejected/unavailable even when baseline was restored.
        retry=call(config['socket'],{**job,'request_id':'new-update'});result['new_update_reply']=retry
        assert not retry.get('ok') and not retry.get('created')
        with contextlib.closing(sqlite3.connect('file:'+str(mount/'journal.db')+'?mode=ro',uri=True)) as db:
            state=json.loads(db.execute('SELECT data FROM state').fetchone()[0])
            row=db.execute('SELECT state,result FROM requests WHERE id=?',(job['request_id'],)).fetchone()
            health=db.execute('SELECT state FROM health WHERE id=1').fetchone()[0]
            assert state['committed']==baseline['committed']
            assert not db.execute("SELECT 1 FROM requests WHERE id='new-update'").fetchone()
            if row:assert row[0] not in {'COMMITTED','ROLLED_BACK','CANCELLED'}
            if phase=='pre':assert row is None
            if phase=='prepare':assert os.readlink(mount/'active.conf')==pointer
            result.update(core_state=state['state'],request_state=row[0] if row else None,request_result=json.loads(row[1]) if row and row[1] else None,storage_health=health)
        result['wire_after']=wire();result['service_exit']=parent.poll()
        if kind=='sqlite_full':
            assert health=='STORAGE_FAILED'
            codes=[(result.get('initial_reply') or {}).get('sqlite_error'),(result.get('cancel_reply') or {}).get('sqlite_error'),(result.get('request_result') or {}).get('sqlite_error')]
            if phase!='cancel':assert 'SQLITE_FULL' in codes
            else:assert result['cancel_reply'].get('sqlite_error')=='SQLITE_FULL'
            assert result['wire_after']=='baseline'
            parent.terminate();parent.wait(3)
            log=(work/'service-restart.log').open('wb')
            parent=subprocess.Popen([sys.executable,'-m','certweft.service',str(cfg)],cwd=P,stdout=log,stderr=subprocess.STDOUT);log.close()
            for _ in range(120):
                if parent.poll() is not None:raise AssertionError('latched_restart_failed')
                response=call(config['socket'],{**job,'request_id':'after-restart'})
                if response.get('reason')=='storage_unavailable':break
                time.sleep(.025)
            else:raise AssertionError('restart_lost_storage_latch')
            result['restart_still_blocks_new_updates']=True
        else:
            # The service cannot persist its health latch on a broken filesystem.
            parent.wait(3);assert parent.returncode==75;result['service_exit']=75
        result['passed']=True
    finally:
        cleanup=True
        if child and alive(child):os.kill(child,signal.SIGKILL)
        if parent and parent.poll() is None:parent.terminate()
        if parent:
            try:parent.wait(3)
            except subprocess.TimeoutExpired:parent.kill();parent.wait();cleanup=False
        tracked=[]
        if (work/'executors.jsonl').exists():tracked=[json.loads(x) for x in (work/'executors.jsonl').read_text().splitlines()]
        for entry in tracked:
            if alive(entry['pid'],entry['start']):os.kill(entry['pid'],signal.SIGKILL)
        if ngpid:
            children=pathlib.Path('/proc',str(ngpid),'task',str(ngpid),'children')
            if children.exists():ngworkers=list(map(int,children.read_text().split()))
            try:run(['/usr/sbin/nginx','-s','quit','-c',work/'nginx.conf'])
            except Exception:cleanup=False
        for _ in range(100):
            if not any(alive(e['pid'],e['start']) for e in tracked) and not any(alive(p) for p in ([ngpid] if ngpid else [])+ngworkers):break
            time.sleep(.03)
        else:cleanup=False
        if mounted:
            try:
                if bound:run(['umount',mount]);bound=False
                run(['umount',mount]);mounted=False
                assert subprocess.run(['mountpoint','-q',str(mount)]).returncode!=0
                if loop:assert subprocess.run(['losetup',loop],capture_output=True).returncode!=0
            except Exception as error:
                cleanup=False;result['mount_cleanup_error']=type(error).__name__+': '+str(error)
        result.update(cleanup_verified=cleanup,tracked_executors=len(tracked),elapsed_seconds=time.monotonic()-t)
        if not mounted and cleanup:shutil.rmtree(work)
        if not cleanup:raise AssertionError('fixture_cleanup_failed: '+json.dumps(result))
    return result

def main():
    if os.geteuid()!=0:raise PermissionError('isolated VM root required')
    os.umask(0o077);source=hashes();out=P/'evidence/storage.json';out.parent.mkdir(exist_ok=True)
    if out.exists():
        archive=P/'evidence/storage-attempts';archive.mkdir(exist_ok=True);shutil.copyfile(out,archive/(str(time.time_ns())+'.json'))
    def publish(d):
        text=json.dumps(d,indent=2);out.with_suffix('.html').write_text('<!doctype html><meta charset="utf-8"><pre>'+html.escape(text)+'</pre>');out.write_text(text)
    report={'passed':False,'status':'in_progress','cases':[],'scope':'formal certweft.service + executor; Nginx; ext4 loop filesystem in isolated Linux VM','untested':['physical medium failures','fsync failure injection','power loss','VM reboot','persistent systemd deployment','controlled DEGRADED repair','automatic quota/history recycling']};publish(report)
    try:
        for kind in ['enospc','readonly','sqlite_full']:
            for phase in ['pre','prepare','post','cancel']:
                try:result=scenario(kind,phase)
                except Exception as error:
                    report['cases'].append({'fault':kind,'phase':phase,'passed':False,'error':type(error).__name__+': '+str(error)});raise
                report['cases'].append(result);publish(report)
        report['passed']=True;report['status']='completed'
    except Exception as e:
        import traceback;traceback.print_exc();report['error']=type(e).__name__+': '+str(e);report['status']='failed'
    report['environment']={'python':sys.version.split()[0],'sqlite':sqlite3.sqlite_version,'openssl':ssl.OPENSSL_VERSION,'kernel':os.uname().release,'machine':os.uname().machine}
    report['source_sha256']=source;report['source_unchanged']=source==hashes();report['passed']=report['passed'] and report['source_unchanged'];publish(report)
    print(json.dumps({'passed':report['passed'],'cases':len(report['cases']),'error':report.get('error')}));return 0 if report['passed'] else 1
if __name__=='__main__':sys.exit(main())
