"""Phased, installed-service normal-VM-reboot qualification; disposable VM only.

Host drives: deployment_vm.py --bootstrap-only; prepare pending; normal VM stop/start;
check pending; prepare committed; stop/start; check committed; prepare reopened;
stop/start; check reopened; finish. Every phase is bounded externally by timeout.
"""
import hashlib,html,json,os,pathlib,signal,sqlite3,ssl,socket,sys,time,grp
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
            cert=pathlib.Path((LAB/'candidate-path').read_text())
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
    plan={'case':case,'boot_id':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'before':before,'stale_core':{'epoch':core['epoch'],'revision':core['revision']},'expected_leaf':expected(before['state']['committed']),'pre_shutdown_memory':memory(int(p['MainPID'])),'old_invocation':p['InvocationID']}
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
        assert obs['boot_id']!=plan['boot_id'] and p['InvocationID']!=plan['old_invocation']
        for key in ['journal_sha256','recovery_sha256','gate_sha256','state','requests','recovery','active']:assert obs[key]==plan['before'][key],key
        assert obs['writer_main_pid']=='0';assert not gate['gate_allows_updates'] and gate['gate']['state']=='RECOVERY_REQUIRED',gate
        # A genuinely valid new request is refused by the recovered Gate, before
        # recovery, rather than only rejecting a malformed/stale request.
        core=cli('status')[0]['result'];cert=pathlib.Path((LAB/'candidate-path').read_text())
        denied,_=cli('submit','--certificate',cert,'--request-id','closed-'+case,'--epoch',core['epoch'],'--revision',core['revision'],user='certweft-operator',ok=False)
        assert not denied['ok'] and denied['reason'] in {'recovery_required','gate_required','updates_closed'},denied
        closed_leaf=wire()
        if case=='pending':assert obs['state']['state']=='APPLYING' and closed_leaf!=plan['expected_leaf']
        else:assert obs['state']['state']=='READY' and closed_leaf==plan['expected_leaf']
        # Stop evidence unit before changing plan; it only runs once on each boot.
        opened,_=cli('recover','--prefix','boot-'+case,timeout=65);assert opened['updates_enabled'];assert wire()==plan['expected_leaf']
        now=cli('status')[0]['result'];assert now['state']=='READY' and now['epoch']!=plan['stale_core']['epoch']
        stale,_=cli('submit','--certificate',cert,'--request-id','stale-'+case,'--epoch',plan['stale_core']['epoch'],'--revision',plan['stale_core']['revision'],'--wait',user='certweft-operator',ok=False)
        assert stale['reason']=='activation_FAILED',stale;assert wire()==plan['expected_leaf']
        assert snapshot()['state']['committed']==plan['before']['state']['committed']
        # Existing completed request is historical, never replayed or rewritten.
        if case in {'committed','reopened'}:
            old=next(row for row in obs['requests'] if row[0]=='reboot-committed');new=next(row for row in snapshot()['requests'] if row[0]=='reboot-committed');assert old==list(new) and new[1]=='COMMITTED'
        payload();entry={'name':case,'passed':True,'before_shutdown':plan['before'],'before_writer_on_new_boot':obs,'new_service_invocation':True,'closed_before_explicit_root_recovery':True,'observed_leaf_before_root_recovery':closed_leaf,'committed_leaf_after_explicit_recovery':wire(),'old_core_rejected_after_reopening':True,'post_ready_check_and_root_recovery_seconds':time.monotonic()-start,'pre_shutdown_writer_memory':plan['pre_shutdown_memory'],'post_recovery_writer_memory':memory(int(p['MainPID']))}
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
