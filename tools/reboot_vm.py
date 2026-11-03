"""Phased, installed-service normal-VM-reboot qualification; disposable VM only.

Host drives: deployment_vm.py --bootstrap-only; prepare pending; normal VM stop/start;
check pending; prepare committed; stop/start; check committed; prepare reopened;
stop/start; check reopened; finish. Every phase is bounded externally by timeout.
"""
import hashlib,html,json,os,pathlib,signal,sqlite3,ssl,socket,sys,time,grp,select
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
from tools.deployment_vm import run,cli,props,wait_ready,memory,assert_empty,P,PY
from tools.executor_vm import hashes
LAB=pathlib.Path('/var/lib/certweft-reboot-lab');STATE=pathlib.Path('/var/lib/certweft')
OUT=P/'evidence/reboot.json';PLAN=LAB/'plan.json'
OBSERVER='''import hashlib,json,os,pathlib,sqlite3,time
lab=pathlib.Path('/var/lib/certweft-reboot-lab');root=pathlib.Path('/var/lib/certweft')
plan=json.loads((lab/'plan.json').read_text())
with sqlite3.connect('file:'+str(root/'journal.db')+'?mode=ro',uri=True) as db:
 state=json.loads(db.execute('SELECT data FROM state WHERE id=1').fetchone()[0])
 requests=list(db.execute('SELECT id,state,result FROM requests ORDER BY id'))
with sqlite3.connect('file:'+str(root/'recovery.db')+'?mode=ro',uri=True) as db:
 recovery=list(db.execute('SELECT id,state,result FROM recovery_requests ORDER BY id'))
value={'boot_id':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'uptime_seconds':float(pathlib.Path('/proc/uptime').read_text().split()[0]),'journal_sha256':hashlib.sha256((root/'journal.db').read_bytes()).hexdigest(),'recovery_sha256':hashlib.sha256((root/'recovery.db').read_bytes()).hexdigest(),'gate_sha256':hashlib.sha256((root/'execution.json').read_bytes()).hexdigest(),'state':state,'requests':requests,'recovery':recovery,'active':os.readlink(root/'active.conf'),'writer_main_pid':os.popen('systemctl show certweft.service -p MainPID --value').read().strip()}
value=json.loads(json.dumps(value)) # normalize SQLite tuples to persisted JSON arrays
assert value['boot_id']!=plan['boot_id'],'same_boot'
for key in ['journal_sha256','recovery_sha256','gate_sha256','state','requests','recovery','active']:
 assert value[key]==plan['before'][key],'changed_before_writer:'+key
assert value['writer_main_pid']=='0','writer_started_before_observation'
target=lab/('observed-'+plan['case']+'.json')
fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
with os.fdopen(fd,'w') as stream:
 json.dump(value,stream);stream.flush();os.fsync(stream.fileno())
'''
UNIT='''[Unit]
Description=Certweft disposable VM read-only pre-service evidence
Before=certweft-nginx.service certweft.service
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /var/lib/certweft-reboot-lab/observe.py
RemainAfterExit=yes
'''
DROP='''[Unit]
Requires=certweft-reboot-observe.service
After=certweft-reboot-observe.service
'''

def publish(r):
    text=json.dumps(r,indent=2);OUT.write_text(text);OUT.with_suffix('.html').write_text('<!doctype html><meta charset="utf-8"><pre>'+html.escape(text)+'</pre>')

def wire():
    ctx=ssl.create_default_context(cafile='/etc/certweft/ca.pem')
    with socket.create_connection(('127.0.0.1',19443),2) as raw:
        with ctx.wrap_socket(raw,server_hostname='localhost') as tls:
            assert not tls.session_reused;tls.sendall(b'GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n');assert tls.recv(4096).startswith(b'HTTP/1.1 200 ')
            return hashlib.sha256(tls.getpeercert(True)).hexdigest()

def snapshot():
    with sqlite3.connect('file:'+str(STATE/'journal.db')+'?mode=ro',uri=True) as db:
        state=json.loads(db.execute('SELECT data FROM state WHERE id=1').fetchone()[0]);requests=list(db.execute('SELECT id,state,result FROM requests ORDER BY id'))
    with sqlite3.connect('file:'+str(STATE/'recovery.db')+'?mode=ro',uri=True) as db:
        recovery=list(db.execute('SELECT id,state,result FROM recovery_requests ORDER BY id'))
    return {'journal_sha256':hashlib.sha256((STATE/'journal.db').read_bytes()).hexdigest(),'recovery_sha256':hashlib.sha256((STATE/'recovery.db').read_bytes()).hexdigest(),'gate_sha256':hashlib.sha256((STATE/'execution.json').read_bytes()).hexdigest(),'state':state,'requests':requests,'recovery':recovery,'active':os.readlink(STATE/'active.conf')}

def expected(name):
    return hashlib.sha256(run(['openssl','x509','-in',STATE/('v-'+name)/'cert.pem','-outform','DER']).stdout).hexdigest()

def boot_pair(plan,obs,current_boot):
    assert obs['boot_id']==current_boot,'observer_not_current_boot'
    assert current_boot!=plan['boot_id'],'same_boot'
    for key in ['journal_sha256','recovery_sha256','gate_sha256','state','requests','recovery','active']:
        assert obs[key]==plan['before'][key],key
    assert obs['writer_main_pid']=='0'

def runtime_identity(p):
    # Inspect the live unit again on every boot, not just an old bootstrap report.
    pid=int(p['MainPID']);assert pid>1 and p['ActiveState']=='active'
    fd=os.pidfd_open(pid)
    try:
        poll=select.poll();poll.register(fd,select.POLLIN);assert not poll.poll(0)
        raw=run(['systemctl','show','certweft.service','-p','FragmentPath','-p','DropInPaths','-p','ExecStart']).stdout.decode()
        unit=dict(line.split('=',1) for line in raw.splitlines() if '=' in line)
        assert unit['FragmentPath']=='/etc/systemd/system/certweft.service'
        assert unit['DropInPaths']=='/etc/systemd/system/certweft.service.d/reboot-evidence.conf'
        expected_args=[PY,'-I','-m','certweft.service','/etc/certweft/writer.json']
        assert unit['ExecStart'].split(' ; ')[1]=='argv[]='+' '.join(expected_args),'loaded_writer_command'
        package=pathlib.Path(payload()['installed_root'])/'certweft/assets/certweft.service'
        assert pathlib.Path(unit['FragmentPath']).read_bytes()==package.read_bytes(),'writer_unit_drift'
        assert pathlib.Path(unit['DropInPaths']).read_text()==DROP,'writer_dropin_drift'
        proc=pathlib.Path('/proc',str(pid));args=proc.joinpath('cmdline').read_bytes().rstrip(b'\0').decode().split('\0')
        assert args==expected_args and os.readlink(proc/'cwd')=='/','live_writer_command'
        mem=memory(pid);assert int(mem['CapEff'],16)==1 and mem['NoNewPrivs']=='1' and mem['Uid'].split()==['0']*4
        current=props('certweft.service');assert current['InvocationID']==p['InvocationID'] and current['MainPID']==str(pid) and not poll.poll(0),'writer_changed_during_observation'
        return {'main_pid':pid,'invocation_id':p['InvocationID'],'cmdline':args,'cwd':'/','unit':unit,'unit_sha256':hashlib.sha256(package.read_bytes()).hexdigest(),'memory':mem}
    finally:os.close(fd)

def public_alternative(case,committed):
    current=expected(committed)
    source_cert=next(c for c in sorted(STATE.glob('v-*/cert.pem')) if hashlib.sha256(run(['openssl','x509','-in',c,'-outform','DER']).stdout).hexdigest()!=current)
    path=pathlib.Path('/var/lib/certweft-candidates')/('reboot-control-'+case+'.pem')
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o640)
    with os.fdopen(fd,'wb') as stream:
        stream.write(source_cert.read_bytes());stream.flush();os.fsync(stream.fileno())
    os.chown(path,0,grp.getgrnam('certweft-operator').gr_gid);path.chmod(0o640)
    return path,hashlib.sha256(run(['openssl','x509','-in',path,'-outform','DER']).stdout).hexdigest()

def activation_control(stale_history,fresh,before_leaf,after_leaf,target_leaf):
    assert stale_history['state']=='FAILED' and stale_history['result']['error']=='Rejected' and not stale_history['result']['expired'],'stale_not_rejected'
    assert fresh['result']['state']=='COMMITTED','fresh_authority_cannot_activate'
    assert after_leaf==target_leaf and after_leaf!=before_leaf,'fresh_activation_not_observed'

def payload():
    bootstrap=json.loads((P/'evidence/boot-bootstrap.json').read_text());assert bootstrap['passed']
    for name,digest in bootstrap['installed_payload'].items():
        assert hashlib.sha256((pathlib.Path(bootstrap['installed_root'])/name).read_bytes()).hexdigest()==digest,'installed_payload_drift'
        assert hashlib.sha256((P/name).read_bytes()).hexdigest()==digest,'source_payload_drift'
    return bootstrap

def prepare(case):
    if case=='pending':
        if LAB.exists():raise AssertionError('existing_reboot_lab_requires_investigation')
        LAB.mkdir(mode=0o700);(LAB/'observe.py').write_text(OBSERVER)
        r={'passed':False,'status':'in_progress','scope':'installed wheel, normal Colima VM shutdown/start; read-only pre-service observer fixture','cases':[],'source_sha256':hashes(),'untested':['sudden power loss','boot zero-gap','storage fault across reboot','unbounded stability','external WAN reachability']}
        b=payload();r['wheel_sha256']=b['wheel_sha256'];r['installed_payload']=b['installed_payload'];publish(r)
        config=pathlib.Path('/etc/certweft/writer.json');original=json.loads(config.read_text());(LAB/'original-config.json').write_text(json.dumps(original))
        config.write_text(json.dumps({**original,'pause_at':'confirmed','marker':str(STATE/'reboot-marker.json')}))
        run(['systemctl','start','certweft.service']);gate,p=wait_ready();assert gate['gate_allows_updates']
        core=cli('status')[0]['result'];baseline=sorted(STATE.glob('v-*/cert.pem'))
        source_cert=next(c for c in baseline if c.parent.name!='v-'+core['committed'])
        candidate=pathlib.Path('/var/lib/certweft-candidates/reboot-baseline.pem');candidate.write_bytes(source_cert.read_bytes());os.chown(candidate,0,grp.getgrnam('certweft-operator').gr_gid);candidate.chmod(0o640);(LAB/'candidate-path').write_text(str(candidate))
        value,_=cli('submit','--certificate',candidate,'--request-id','reboot-pending','--epoch',core['epoch'],'--revision',core['revision'],user='certweft-operator');assert value['ok']
        end=time.monotonic()+4
        while not (STATE/'reboot-marker.json').exists() and time.monotonic()<end:time.sleep(.02)
        assert (STATE/'reboot-marker.json').exists(),'formal_executor_not_paused'
        assert snapshot()['state']['state']=='APPLYING';assert wire()!=expected(core['committed'])
        # Freeze only the validated writer PID; executor is already SIGSTOP at its
        # formal checkpoint. Normal shutdown must SIGKILL after its stop budget.
        current=props('certweft.service');assert current['InvocationID']==p['InvocationID'] and int(current['MainPID'])>1
        fd=os.pidfd_open(int(current['MainPID']))
        try:signal.pidfd_send_signal(fd,signal.SIGSTOP)
        finally:os.close(fd)
        config.write_text(json.dumps(original)) # next boot has no pause fixture
    elif case in {'committed','reopened'}:
        r=json.loads(OUT.read_text());assert r['cases'][-1]['name']==('pending' if case=='committed' else 'committed')
        gate,p=wait_ready();assert gate['gate_allows_updates']
        core=cli('status')[0]['result']
        if case=='committed':
            cert,_=public_alternative('prepare-committed',core['committed'])
            v,_=cli('submit','--certificate',cert,'--request-id','reboot-committed','--epoch',core['epoch'],'--revision',core['revision'],'--wait',user='certweft-operator');assert v['result']['state']=='COMMITTED'
            assert wire()==expected(cli('status')[0]['result']['committed'])
    else:raise AssertionError('unknown_case')
    r=json.loads(OUT.read_text());assert r['source_sha256']==hashes(),'source_changed'
    core=cli('status')[0]['result'] if case!='pending' else core
    if case!='pending':
        current=props('certweft.service');assert current['InvocationID']==p['InvocationID'] and int(current['MainPID'])>1
        fd=os.pidfd_open(int(current['MainPID']))
        try:signal.pidfd_send_signal(fd,signal.SIGSTOP)
        finally:os.close(fd)
    before=snapshot()
    plan={'case':case,'boot_id':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'before':before,'stale_core':{'epoch':core['epoch'],'revision':core['revision']},'expected_leaf':expected(before['state']['committed']),'candidate_leaf':expected(before['state']['candidate']) if before['state'].get('candidate') else None,'pre_shutdown_memory':memory(int(p['MainPID'])),'old_invocation':p['InvocationID']}
    PLAN.write_text(json.dumps(plan));os.chmod(PLAN,0o600)
    pathlib.Path('/etc/systemd/system/certweft-reboot-observe.service').write_text(UNIT)
    for unit in ['certweft.service']:
        d=pathlib.Path('/etc/systemd/system',unit+'.d');d.mkdir(exist_ok=True);(d/'reboot-evidence.conf').write_text(DROP)
    run(['systemctl','daemon-reload']);run(['systemctl','enable','certweft.service'])
    assert run(['systemctl','is-enabled','certweft.service']).stdout.strip()==b'enabled'
    r['pending_case']=case;publish(r)
    print(json.dumps({'prepared':case,'requires_normal_vm_stop_start':True}))

def check(case):
    r=json.loads(OUT.read_text());assert r['source_sha256']==hashes();plan=json.loads(PLAN.read_text());assert plan['case']==case
    try:
        start=time.monotonic();gate,p=wait_ready();obs=json.loads((LAB/('observed-'+case+'.json')).read_text())
        current_boot=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip();boot_pair(plan,obs,current_boot)
        assert p['InvocationID']!=plan['old_invocation']
        runtime=runtime_identity(p)
        assert not gate['gate_allows_updates'] and gate['gate']['state']=='RECOVERY_REQUIRED',gate
        core=cli('status')[0]['result'];cert=pathlib.Path((LAB/'candidate-path').read_text())
        denied,_=cli('submit','--certificate',cert,'--request-id','closed-'+case,'--epoch',core['epoch'],'--revision',core['revision'],user='certweft-operator',ok=False)
        assert not denied['ok'] and denied['reason']=='recovery_required',denied
        closed_leaf=wire()
        if case=='pending':assert obs['state']['state']=='APPLYING' and closed_leaf==plan['candidate_leaf'] and closed_leaf!=plan['expected_leaf']
        else:assert obs['state']['state']=='READY' and closed_leaf==plan['expected_leaf']
        opened,_=cli('recover','--prefix','boot-'+case,timeout=65);assert opened['updates_enabled']
        restored_leaf=wire();assert restored_leaf==plan['expected_leaf']
        root_history=[cli('recovery-request-status','--request-id',identity)[0]['result'] for identity in opened['requests']]
        now=cli('status')[0]['result'];assert now['state']=='READY' and now['epoch']!=plan['stale_core']['epoch']
        # Same valid certificate, same timeout and operator; only fresh request ID
        # and epoch/revision differ between the negative and positive controls.
        control_cert,target_leaf=public_alternative(case,now['committed'])
        stale,_=cli('submit','--certificate',control_cert,'--request-id','stale-'+case,'--epoch',plan['stale_core']['epoch'],'--revision',plan['stale_core']['revision'],'--wait',user='certweft-operator',ok=False)
        assert stale['reason']=='activation_FAILED',stale
        stale_history=cli('request-status','--request-id','stale-'+case)[0]['result']
        assert wire()==restored_leaf and snapshot()['state']==now,'stale_changed_core_or_wire'
        fresh,_=cli('submit','--certificate',control_cert,'--request-id','fresh-'+case,'--epoch',now['epoch'],'--revision',now['revision'],'--wait',user='certweft-operator')
        fresh_leaf=wire();activation_control(stale_history,fresh,restored_leaf,fresh_leaf,target_leaf)
        if case in {'committed','reopened'}:
            old=next(row for row in obs['requests'] if row[0]=='reboot-committed');new=next(row for row in snapshot()['requests'] if row[0]=='reboot-committed');assert old==list(new) and new[1]=='COMMITTED'
        payload();entry={'name':case,'passed':True,'old_boot_id':plan['boot_id'],'current_boot_id':current_boot,'old_invocation_id':plan['old_invocation'],'writer_runtime':runtime,'before_shutdown':plan['before'],'before_writer_on_new_boot':obs,'new_service_invocation':True,'closed_gate_response':gate,'closed_valid_request_response':denied,'closed_before_explicit_root_recovery':True,'expected_candidate_leaf':plan['candidate_leaf'],'observed_leaf_before_root_recovery':closed_leaf,'committed_leaf_after_explicit_recovery':restored_leaf,'root_recovery_response':opened,'root_recovery_history':root_history,'stale_cli_response':stale,'stale_request_history':stale_history,'old_core_rejected_after_reopening':True,'fresh_activation_after_reopening':{'response':fresh,'prior_core':now,'old_leaf':restored_leaf,'expected_leaf':target_leaf,'wire_leaf':fresh_leaf},'post_ready_check_recovery_and_control_seconds':time.monotonic()-start,'pre_shutdown_writer_memory':plan['pre_shutdown_memory'],'post_control_writer_memory':memory(int(p['MainPID']))}
        r['cases'].append(entry);r.pop('pending_case',None);publish(r);print(json.dumps({'checked':case,'passed':True}))
    except Exception as e:
        r.update(passed=False,status='failed',error=type(e).__name__+': '+str(e));publish(r);raise

def finish():
    r=json.loads(OUT.read_text());assert [c['name'] for c in r['cases']]==['pending','committed','reopened']
    run(['systemctl','disable','--now','certweft.service']);run(['systemctl','stop','certweft-nginx.service'])
    r['cleanup']={u:assert_empty(u) for u in ['certweft.service','certweft-nginx.service']}
    for unit in ['certweft.service']:
        (pathlib.Path('/etc/systemd/system',unit+'.d')/'reboot-evidence.conf').unlink();pathlib.Path('/etc/systemd/system',unit+'.d').rmdir()
    run(['systemctl','stop','certweft-reboot-observe.service']);pathlib.Path('/etc/systemd/system/certweft-reboot-observe.service').unlink();run(['systemctl','daemon-reload'])
    assert run(['systemctl','is-enabled','certweft.service'],ok=False).stdout.strip()==b'disabled'
    payload();r.update(source_unchanged=r['source_sha256']==hashes(),status='completed');r['passed']=r['source_unchanged'] and all(c['passed'] for c in r['cases']);publish(r);assert r['passed'];print(json.dumps({'passed':True,'cases':3,'temporary_boot_hooks_removed':True,'private_evidence_retained_inside_vm':True}))

if __name__=='__main__':
    if os.geteuid()!=0 or os.environ.get('CERTWEFT_REBOOT_VM')!='1':raise PermissionError('explicit disposable Linux VM required')
    os.umask(0o077)
    if sys.argv[1]=='prepare':prepare(sys.argv[2])
    elif sys.argv[1]=='check':check(sys.argv[2])
    elif sys.argv[1]=='finish':finish()
    else:raise ValueError('unknown_phase')
