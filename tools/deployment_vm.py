"""Installed-wheel/systemd qualification. Run only in a disposable Linux VM."""
import contextlib,hashlib,html,json,os,pathlib,pwd,grp,secrets,shutil,signal,socket,sqlite3,ssl,subprocess,sys,tempfile,time,traceback,zipfile
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
from tools.executor_vm import hashes
P=pathlib.Path(__file__).resolve().parents[1];PY='/opt/certweft/bin/python';CLI=[PY,'-I','-m','certweft.cli'];UNITS=['certweft.service','certweft-nginx.service'];OWNER=pathlib.Path('/var/tmp/certweft-deployment-owner.json')
MANAGED=['/etc/certweft','/var/lib/certweft','/var/lib/certweft-candidates','/var/log/certweft-nginx']

def run(args,timeout=40,ok=True,umask=-1):
    r=subprocess.run(list(map(str,args)),cwd='/',capture_output=True,timeout=timeout,umask=umask)
    if ok and r.returncode:raise RuntimeError('command_failed:'+str(args[0])+':'+str(r.returncode))
    return r

def reset(unit='certweft.service'):
    r=run(['systemctl','reset-failed',unit],ok=False)
    if r.returncode and b'not loaded' not in r.stderr:raise AssertionError('unit_reset_failed')

def props(unit):
    r=run(['systemctl','show',unit,'-p','MainPID','-p','InvocationID','-p','ActiveState','-p','SubState','-p','Result','-p','ExecMainStatus','-p','ControlGroup','-p','NRestarts','-p','User','-p','CapabilityBoundingSet','-p','KillMode','-p','Restart','-p','RestartPreventExitStatus','-p','StartLimitBurst','-p','StartLimitIntervalUSec'])
    return dict(line.split('=',1) for line in r.stdout.decode().splitlines() if '=' in line)

def cli(*args,user=None,ok=True,timeout=30):
    cmd=CLI+list(map(str,args));cmd=['runuser','-u',user,'--',*cmd] if user else cmd
    r=run(cmd,timeout,False)
    if ok and r.returncode:raise AssertionError('cli_failed:'+str(args[0])+':'+r.stderr.decode()[-400:])
    payload=r.stdout if r.returncode==0 else r.stderr
    try:v=json.loads(payload)
    except ValueError:raise AssertionError('cli_not_json')
    return v,r

def wait_ready(old=None):
    until=time.monotonic()+15
    while time.monotonic()<until:
        p=props('certweft.service')
        if p['ActiveState']=='active' and (old is None or p['InvocationID']!=old):
            try:
                value,_=cli('gate',timeout=4)
                if value['ok']:return value,p
            except (OSError,AssertionError):pass
        time.sleep(.05)
    raise AssertionError('installed_service_not_ready:'+str(props('certweft.service')))

def kill_main(p):
    pid=int(p['MainPID'])
    if pid<=1 or p['ActiveState']!='active':raise AssertionError('no_live_unit_main')
    fd=os.pidfd_open(pid)
    try:
        current=props('certweft.service')
        if current['MainPID']!=p['MainPID'] or current['InvocationID']!=p['InvocationID']:raise AssertionError('unit_identity_changed_before_kill')
        if p['ControlGroup'] not in pathlib.Path('/proc',str(pid),'cgroup').read_text():raise AssertionError('unit_cgroup_mismatch')
        signal.pidfd_send_signal(fd,signal.SIGKILL)
    finally:os.close(fd)

def alive(pid):
    try:return pathlib.Path('/proc',str(pid),'stat').read_text().split()[2]!='Z'
    except (FileNotFoundError,ProcessLookupError):return False

def memory(pid):return {l.split(':')[0]:l.split(':')[1].strip() for l in pathlib.Path('/proc',str(pid),'status').read_text().splitlines() if l.startswith(('VmRSS:','VmHWM:','CapEff:','NoNewPrivs:','Uid:','Gid:'))}

def assert_empty(unit):
    p=props(unit);assert p['MainPID']=='0',p
    group=pathlib.Path('/sys/fs/cgroup'+p['ControlGroup']) if p['ControlGroup'] else None
    if group and group.exists():assert not (group/'cgroup.procs').read_text().strip(),'unit_cgroup_not_empty'
    return {'main_pid_zero':True,'cgroup_empty_or_removed':True}

def owned_reset():
    if not OWNER.exists():return
    owner=json.loads(OWNER.read_text());assert owner.get('scope')=='disposable-certweft-deployment'
    old_ca=owner.get('ca_pid')
    if old_ca and alive(old_ca):
        command=pathlib.Path('/proc',str(old_ca),'cmdline').read_bytes()
        if (owner['work']+'/ca/config/ca.json').encode() not in command:raise AssertionError('unknown_ca_pid')
        os.kill(old_ca,signal.SIGTERM)
        until=time.monotonic()+3
        while alive(old_ca) and time.monotonic()<until:time.sleep(.02)
        if alive(old_ca):raise AssertionError('old_ca_did_not_exit')
    for unit in ['certweft-issue@first.service','certweft-issue@second.service','certweft-issue@after.service',*UNITS]:run(['systemctl','stop',unit],ok=False)
    for unit in UNITS:assert_empty(unit);reset(unit)
    for name in ['certweft.service','certweft-nginx.service','certweft-issue@.service']:(pathlib.Path('/etc/systemd/system')/name).unlink(missing_ok=True)
    for path in MANAGED:shutil.rmtree(path,ignore_errors=False) if pathlib.Path(path).exists() else None
    for user in ['certweft-operator','certweft-signer']:run(['userdel',user],ok=False);run(['groupdel',user],ok=False)
    run(['systemctl','daemon-reload']);OWNER.unlink()

def main():
    if os.geteuid()!=0 or os.environ.get('CERTWEFT_DEPLOYMENT_VM')!='1':raise PermissionError('explicit disposable Linux VM required')
    bootstrap='--bootstrap-only' in sys.argv
    os.umask(0o077);source=hashes();out=P/('evidence/boot-bootstrap.json' if bootstrap else 'evidence/deployment.json');archive=P/'evidence/deployment-attempts';archive.mkdir(exist_ok=True)
    if out.exists():shutil.copyfile(out,archive/(str(time.time_ns())+'.json'))
    report={'passed':False,'status':'in_progress','cases':[],'scope':'wheel-installed fixed systemd services in a newly created, provisioned Ubuntu VM; application reset between development attempts','untested':['VM reboot recovery','power loss','boot zero-gap','D-state termination','remote CA network','production PKI enrollment','multi-instance deployment','unbounded operation']}
    def publish():
        t=json.dumps(report,indent=2);out.write_text(t);out.with_suffix('.html').write_text('<!doctype html><meta charset="utf-8"><pre>'+html.escape(t)+'</pre>')
    def case(name,fn):
        t=time.monotonic()
        try:detail=fn()
        except Exception as error:
            report['cases'].append({'name':name,'passed':False,'error':type(error).__name__});publish();raise
        report['cases'].append({'name':name,'passed':True,'seconds':time.monotonic()-t,'detail':detail});publish();return detail
    publish();work=pathlib.Path(tempfile.mkdtemp(prefix='cw-deployment-',dir='/var/tmp'));ca=None;external=None;cleanup=False;secret=secrets.token_urlsafe(32)
    def wire():
        ctx=ssl.create_default_context(cafile='/etc/certweft/ca.pem')
        with socket.create_connection(('127.0.0.1',19443),2) as raw:
            with ctx.wrap_socket(raw,server_hostname='localhost') as s:
                assert not s.session_reused;s.sendall(b'GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n');data=s.recv(4096)
                assert data.startswith(b'HTTP/1.1 200 ')
                return hashlib.sha256(s.getpeercert(True)).hexdigest()
    def issue(identity,observe=False):
        unit='certweft-issue@'+identity+'.service'
        if observe:os.kill(ca.pid,signal.SIGSTOP)
        run(['systemctl','start','--no-block',unit]);observed={}
        try:
            if observe:
                for _ in range(100):
                    p=props(unit);pid=int(p['MainPID'])
                    if pid and pathlib.Path('/proc',str(pid),'exe').exists() and b'certweft.cli' in pathlib.Path('/proc',str(pid),'cmdline').read_bytes():break
                    time.sleep(.02)
                else:raise AssertionError('signer_not_running')
                observed=memory(pid);uid=pwd.getpwnam('certweft-signer').pw_uid
                assert int(observed['Uid:'.rstrip(':')].split()[1])==uid
                assert int(observed['CapEff'],16)==0 and observed['NoNewPrivs']=='1'
                env=pathlib.Path('/proc',str(pid),'environ').read_bytes();assert secret.encode() not in env
                for target in ['/etc/certweft/provisioner-password','/etc/certweft/service.key','/proc/'+str(pid)+'/root/run/credentials/'+unit+'/provisioner-password']:
                    denied=run(['runuser','-u','certweft-operator','--','cat',target],ok=False);assert denied.returncode!=0
                denied=run(['runuser','-u','certweft-signer','--','cat','/etc/certweft/provisioner-password'],ok=False);assert denied.returncode!=0
        finally:
            if observe:os.kill(ca.pid,signal.SIGCONT)
        for _ in range(400):
            p=props(unit)
            if p['ActiveState'] not in {'activating','active'}:break
            time.sleep(.03)
        assert p['Result']=='success' and p['ExecMainStatus']=='0',p
        cert=pathlib.Path('/var/lib/certweft-candidates')/identity/'cert.pem';assert cert.exists()
        log=run(['journalctl','-u',unit,'--no-pager','-o','cat']).stdout;assert secret.encode() not in log
        assert not pathlib.Path('/run/credentials',unit).exists()
        return {'certificate':cert,'observed':observed,'cleanup':assert_empty(unit)}
    def activate(identity,cert):
        st,_=cli('status',user='certweft-operator');core=st['result'];old=wire();start=time.monotonic()
        value,_=cli('submit','--certificate',cert,'--request-id',identity,'--epoch',core['epoch'],'--revision',core['revision'],'--wait',user='certweft-operator')
        assert value['result']['state']=='COMMITTED';new=wire();assert new!=old
        expected=hashlib.sha256(run(['openssl','x509','-in',cert,'-outform','DER']).stdout).hexdigest();assert new==expected
        return {'request_state':'COMMITTED','old_leaf_sha256':old,'new_leaf_sha256':new,'expected_leaf_sha256':expected,'activation_cli_seconds':time.monotonic()-start}
    try:
        owned_reset()
        baseline={'managed_paths_absent':all(not pathlib.Path(p).exists() for p in MANAGED),'units_absent':all(not (pathlib.Path('/etc/systemd/system')/u).exists() for u in ['certweft.service','certweft-nginx.service','certweft-issue@.service'])}
        accounts_absent=True
        for name in ['certweft-operator','certweft-signer']:
            for lookup in [pwd.getpwnam,grp.getgrnam]:
                try:lookup(name);accounts_absent=False
                except KeyError:pass
        baseline['accounts_and_groups_absent']=accounts_absent
        assert all(baseline.values())
        OWNER.write_text(json.dumps({'scope':'disposable-certweft-deployment','work':str(work)}));OWNER.chmod(0o600)
        report['baseline']=baseline;report['environment']={'python':sys.version.split()[0],'kernel':os.uname().release,'architecture':os.uname().machine,'systemd':run(['systemctl','--version']).stdout.decode().splitlines()[0]}
        report['environment'].update(step_version=run(['/usr/local/bin/step','version']).stdout.decode().splitlines()[0],ca_version=run(['/usr/local/bin/step-ca','version']).stdout.decode().splitlines()[0],nginx_version=run(['/usr/sbin/nginx','-v']).stderr.decode().strip(),step_sha256=hashlib.sha256(pathlib.Path('/usr/local/bin/step').read_bytes()).hexdigest(),ca_sha256=hashlib.sha256(pathlib.Path('/usr/local/bin/step-ca').read_bytes()).hexdigest())
        def package():
            wheels=work/'wheels';wheels.mkdir();run([PY,'-m','pip','wheel','--no-deps',P,'--wheel-dir',wheels],timeout=90)
            wheel=next(wheels.glob('certweft-*.whl'));run([PY,'-m','pip','install','--no-deps','--force-reinstall',wheel],timeout=40,umask=0o022)
            payload={}
            with zipfile.ZipFile(wheel) as z:
                for name in z.namelist():
                    if name.startswith('certweft/') and not name.endswith('/'):payload[name]=hashlib.sha256(z.read(name)).hexdigest()
            script="import certweft,json,pathlib;print(json.dumps({'module':certweft.__file__,'root':str(pathlib.Path(certweft.__file__).parent.parent)}))"
            location=json.loads(run([PY,'-I','-c',script]).stdout);assert location['module'].startswith('/opt/certweft/') and str(P) not in location['module']
            root=pathlib.Path(location['root'])
            for name,sha in payload.items():assert hashlib.sha256((root/name).read_bytes()).hexdigest()==sha
            report['installed_payload']=payload;report['installed_root']=location['root'];report['wheel_sha256']=hashlib.sha256(wheel.read_bytes()).hexdigest()
            return {'version':'0.0.2','module':location['module'],'wheel_sha256':report['wheel_sha256'],'payload_files':len(payload)}
        case('wheel_install_and_payload',package)
        os.environ['STEPPATH']=str(work/'ca');(work/'ca-pass').write_text(secrets.token_urlsafe(32));(work/'prov-pass').write_text(secret)
        run(['/usr/local/bin/step','ca','init','--name','Certweft deployment fixture','--dns','localhost','--address','127.0.0.1:19091','--provisioner','exploration','--password-file',work/'ca-pass','--provisioner-password-file',work/'prov-pass'],timeout=30)
        cfgpath=work/'ca/config/ca.json';cfg=json.loads(cfgpath.read_text());prov=cfg['authority']['provisioners'][0];prov['claims']={'minTLSCertDuration':'5m','maxTLSCertDuration':'1h','defaultTLSCertDuration':'30m','disableRenewal':True,'enableSSHCA':False}
        installed=pathlib.Path(report['installed_root'])/'certweft/assets/server.tpl';prov['options']={'x509':{'templateFile':str(installed)}};cfgpath.write_text(json.dumps(cfg))
        ca=subprocess.Popen(['/usr/local/bin/step-ca',str(cfgpath),'--password-file',str(work/'ca-pass')],cwd='/',stdout=(work/'ca.log').open('wb'),stderr=subprocess.STDOUT,start_new_session=True)
        owner=json.loads(OWNER.read_text());owner['ca_pid']=ca.pid;OWNER.write_text(json.dumps(owner))
        root=work/'ca/certs/root_ca.crt'
        for _ in range(80):
            if run(['/usr/local/bin/step','ca','health','--ca-url','https://localhost:19091','--root',root],ok=False).returncode==0:break
            time.sleep(.05)
        else:raise AssertionError('ca_not_ready')
        key=work/'service.key';csr=work/'baseline.csr';cert=work/'baseline.pem'
        run(['openssl','ecparam','-name','prime256v1','-genkey','-noout','-out',key]);run(['openssl','req','-new','-key',key,'-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost','-addext','extendedKeyUsage=serverAuth','-out',csr])
        run(['/usr/local/bin/step','ca','sign',csr,cert,'--ca-url','https://localhost:19091','--root',root,'--provisioner','exploration','--provisioner-password-file',work/'prov-pass','--not-after','1h'])
        def install():
            value,_=cli('install','--certificate',cert,'--key',key,'--ca-root',root,'--credential',work/'prov-pass','--issuer-url','https://localhost:19091','--step','/usr/local/bin/step')
            assert value['installed'] and not value['started'];run(['systemd-analyze','verify','/etc/systemd/system/certweft.service','/etc/systemd/system/certweft-nginx.service','/etc/systemd/system/certweft-issue@.service'])
            run(['systemctl','start','certweft.service']);gate,p=wait_ready();assert gate['gate_allows_updates']
            cmd=pathlib.Path('/proc',p['MainPID'],'cmdline').read_bytes();assert b'-I\x00-m\x00certweft.service' in cmd and str(P).encode() not in cmd
            assert os.readlink('/proc/'+p['MainPID']+'/cwd')=='/'
            denied,_=cli('gate',user='certweft-operator',ok=False);assert denied['reason']=='admin_required'
            for path in ['/etc/certweft/writer.json','/etc/certweft/provisioner-password','/etc/certweft/service.key','/var/lib/certweft/journal.db']:
                assert run(['runuser','-u','certweft-operator','--','cat',path],ok=False).returncode!=0
            measured=memory(int(p['MainPID']));assert int(measured['CapEff'],16)==1 and measured['NoNewPrivs']=='1'
            return {'systemd':p,'service_memory':measured,'initial_updates_enabled':True,'operator_private_reads_denied':True}
        case('documented_install_and_start',install)
        first=case('credential_delivery_and_real_ca_issuance',lambda:{k:str(v) if isinstance(v,pathlib.Path) else v for k,v in issue('first',True).items()})
        case('installed_controller_real_activation',lambda:activate('installed-first',pathlib.Path(first['certificate'])))
        if not bootstrap:
            def fail_recover():
                # Real SQLite pager capacity failure on normal COMMIT, not RAISE().
                state=pathlib.Path('/var/lib/certweft');config=pathlib.Path('/etc/certweft/writer.json');original=json.loads(config.read_text());run(['systemctl','stop','certweft.service'])
                with sqlite3.connect(state/'journal.db') as db:
                    db.execute('CREATE TABLE deploy_pressure(data BLOB)');db.execute("CREATE TRIGGER deploy_full BEFORE UPDATE ON requests WHEN NEW.state='COMMITTED' BEGIN INSERT INTO deploy_pressure VALUES(zeroblob(1048576)); END");limit=db.execute('PRAGMA page_count').fetchone()[0]+1
                config.write_text(json.dumps({**original,'sqlite_max_pages':limit}));run(['systemctl','start','certweft.service']);wait_ready()
                second=issue('second')['certificate'];st,_=cli('status',user='certweft-operator');core=st['result']
                value,_=cli('submit','--certificate',second,'--request-id','disk-failure','--epoch',core['epoch'],'--revision',core['revision'],'--wait',user='certweft-operator',ok=False);assert value['reason']=='activation_DEGRADED',value
                history,_=cli('request-status','--request-id','disk-failure');assert history['result']['result']['sqlite_error']=='SQLITE_FULL',history
                run(['systemctl','stop','certweft.service'])
                with sqlite3.connect(state/'journal.db') as db:db.execute('DROP TRIGGER deploy_full');db.execute('DROP TABLE deploy_pressure')
                config.write_text(json.dumps(original));run(['systemctl','start','certweft.service']);gate,_=wait_ready();assert not gate['gate_allows_updates']
                restored,_=cli('recover','--prefix','repair-one',timeout=60);assert restored['updates_enabled']
                third=issue('after')['certificate'];actual=activate('after-repair',third)
                return {'actual_sqlite_full':True,'failure_state':'DEGRADED','repair_restart_still_closed':True,'explicit_root_recovery_opened':True,'follow_up_activation':actual}
            case('storage_failure_repair_reopen_and_update',fail_recover)
            def crash_takeover():
                config=pathlib.Path('/etc/certweft/writer.json');original=json.loads(config.read_text());run(['systemctl','stop','certweft.service']);reset()
                marker=pathlib.Path('/var/lib/certweft/crash-marker.json');config.write_text(json.dumps({**original,'pause_at':'confirmed','marker':str(marker)}));run(['systemctl','start','certweft.service']);gate,p=wait_ready();assert not gate['gate_allows_updates']
                cli('recover','--prefix','crash-ready',timeout=60)
                st,_=cli('status',user='certweft-operator');core=st['result'];cli('submit','--certificate',first['certificate'],'--request-id','crash-pending','--epoch',core['epoch'],'--revision',core['revision'],user='certweft-operator')
                for _ in range(100):
                    if marker.exists():break
                    time.sleep(.03)
                else:raise AssertionError('formal_executor_checkpoint_missing')
                child=json.loads(marker.read_text())['pid'];old=p['InvocationID'];oldpid=int(p['MainPID']);before=memory(child);start=time.monotonic();kill_main(p)
                gate,new=wait_ready(old);elapsed=time.monotonic()-start;assert not alive(child) and not alive(oldpid)
                assert not gate['gate_allows_updates'];assert pathlib.Path('/var/lib/certweft/lifetime.lock').exists()
                stale,_=cli('submit','--certificate',first['certificate'],'--request-id','old-after-crash','--epoch',core['epoch'],'--revision',core['revision'],user='certweft-operator',ok=False);assert not stale['ok']
                run(['systemctl','stop','certweft.service']);assert_empty('certweft.service');config.write_text(json.dumps(original))
                run(['systemctl','start','certweft.service']);wait_ready();cli('recover','--prefix','crash-after',timeout=60);preserved=wire()
                old,_=cli('submit','--certificate',first['certificate'],'--request-id','stale-after-recovery','--epoch',core['epoch'],'--revision',core['revision'],'--wait',user='certweft-operator',ok=False)
                assert old['reason']=='activation_FAILED' and wire()==preserved,old
                run(['systemctl','stop','certweft.service']);assert_empty('certweft.service')
                return {'post_recovery_stale_activation_rejected_without_wire_change':True,'old_executor_dead_before_new_ready':True,'new_invocation':new['InvocationID']!=old,'closed_after_crash':True,'old_operation_denied':True,'sigkill_to_observed_new_ready_seconds':elapsed,'executor_memory_before_kill':before,'systemd':new}
            case('systemd_sigkill_takeover_and_stale_request',crash_takeover)
            def external_executor():
                nonlocal external
                lease='/var/lib/certweft/lifetime.lock';fd=os.open(lease,os.O_RDWR);import fcntl;fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
                # Real installed executor waits for its message, retaining the same
                # lifetime lease. It is deliberately outside the writer unit cgroup.
                external=subprocess.Popen([PY,'-I','-m','certweft.executor',str(fd)],pass_fds=(fd,),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,cwd='/');os.close(fd)
                reset();r=run(['systemctl','start','certweft.service'],ok=False)
                for _ in range(60):
                    p=props('certweft.service')
                    if p['ActiveState']=='failed':break
                    time.sleep(.03)
                assert p['ExecMainStatus']=='73' and p['NRestarts']=='0' and external.poll() is None,p
                external.kill();external.communicate(timeout=3);reset();run(['systemctl','start','certweft.service']);gate,_=wait_ready();assert not gate['gate_allows_updates']
                return {'real_installed_executor_holds_lease':True,'unit_exit_status':73,'automatic_restarts_while_occupied':0,'takeover_only_after_executor_exit':True,'new_session_closed':True}
            case('outside_cgroup_executor_blocks_takeover',external_executor)
            def limits():
                run(['systemctl','stop','certweft.service']);reset();run(['systemctl','start','certweft.service']);gate,p=wait_ready();observed=[]
                cursor=run(['journalctl','-u','certweft.service','-n','0','--show-cursor','--no-pager']).stdout.decode().strip().split('-- cursor: ')[-1]
                for _ in range(4):
                    old=p['InvocationID'];kill_main(p)
                    until=time.monotonic()+8
                    while time.monotonic()<until:
                        p=props('certweft.service')
                        if p['ActiveState']=='failed' and p['MainPID']=='0':break
                        if p['ActiveState']=='active' and p['InvocationID']!=old and int(p['MainPID'])>1:
                            _,p=wait_ready(old);break
                        time.sleep(.03)
                    observed.append({'active':p['ActiveState'],'result':p['Result'],'nrestarts':p['NRestarts']})
                    if p['ActiveState']=='failed' and p['MainPID']=='0':break
                journal=run(['journalctl','-u','certweft.service','--after-cursor',cursor,'--no-pager','-o','cat']).stdout
                assert p['ActiveState']=='failed' and p['MainPID']=='0' and p['NRestarts']=='3',p
                assert b'Start request repeated too quickly' in journal,'rate_limit_not_observed'
                refused=run(['systemctl','start','certweft.service'],ok=False);assert refused.returncode!=0 and props('certweft.service')['MainPID']=='0'
                assert_empty('certweft.service');reset();run(['systemctl','start','certweft.service']);gate,_=wait_ready();assert not gate['gate_allows_updates']
                return {'configured_burst':3,'configured_interval_seconds':60,'observed':observed,'this_run_rate_limit_journal_observed':True,'explicit_start_rejected_before_reset':True,'bounded_restart_stop':True,'operator_reset_still_closed':True}
            case('restart_limit_and_explicit_reset',limits)
        # Inspect installed bytes again after all systemd operations.
        for name,sha in report['installed_payload'].items():assert hashlib.sha256((pathlib.Path(report['installed_root'])/name).read_bytes()).hexdigest()==sha
        for unit in UNITS:
            log=run(['journalctl','-u',unit,'--no-pager','-o','cat']).stdout;assert secret.encode() not in log
        disk=list(pathlib.Path('/var/lib/certweft').rglob('*'));unique={}
        for path in disk:
            if path.is_file() and not path.is_symlink():
                st=path.stat();unique[(st.st_dev,st.st_ino)]=st
        report['state_disk']={'scope':'unique regular file inodes after scenarios; excludes symlink targets, directories and filesystem metadata','logical_bytes':sum(s.st_size for s in unique.values()),'allocated_bytes':sum(s.st_blocks*512 for s in unique.values()),'files':len(unique)}
        report.update(passed=True,status='completed')
    except Exception as error:
        traceback.print_exc();report.update(status='failed',error=type(error).__name__+': '+str(error))
    finally:
        if external and external.poll() is None:external.kill();external.communicate(timeout=3)
        for unit in ['certweft-issue@first.service','certweft-issue@second.service','certweft-issue@after.service',*UNITS]:run(['systemctl','stop',unit],ok=False)
        try:
            report['stop_cleanup']={u:assert_empty(u) for u in UNITS};cleanup=True
        except Exception as e:report['cleanup_error']=type(e).__name__;cleanup=False
        if ca:
            os.kill(ca.pid,signal.SIGCONT) if alive(ca.pid) else None
            if ca.poll() is None:ca.terminate()
            ca.wait(timeout=5)
        report['cleanup_verified']=cleanup and (ca is None or not alive(ca.pid))
        report['private_fixture_retained_inside_vm']=True
    report.update(source_sha256=source,source_unchanged=source==hashes());report['passed']=report['passed'] and report['source_unchanged'] and report['cleanup_verified']
    if secret in json.dumps(report):raise AssertionError('secret_in_public_report')
    publish();print(json.dumps({'passed':report['passed'],'cases':len(report['cases']),'error':report.get('error')}));return 0 if report['passed'] else 1
if __name__=='__main__':sys.exit(main())
