"""Installed storage-fault boot/repair fixture. Explicit disposable Linux VM only.

Uses its own 32 MiB ext4 image and fixed state mount; never fills/remounts root.
All recovery and activation run through the installed CLI/systemd service.
"""
import contextlib,errno,hashlib,html,json,os,pathlib,shutil,signal,sqlite3,sys,time
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
from tools.deployment_vm import run,cli,props,wait_ready,assert_empty,reset,P
from tools.executor_vm import hashes
from tools.reboot_vm import snapshot,expected,wire,public_alternative,activation_control,runtime_identity,OBSERVER,UNIT
LAB=pathlib.Path('/var/lib/certweft-storage-reboot-lab');STATE=pathlib.Path('/var/lib/certweft');OUT=P/'evidence/storage-reboot.json'
MOUNT='var-lib-certweft.mount';OBUNIT='certweft-reboot-observe.service';DROP='''[Unit]
Requires=certweft-reboot-observe.service var-lib-certweft.mount
After=certweft-reboot-observe.service var-lib-certweft.mount
'''

REPAIR_DROP='''[Unit]
Requires=var-lib-certweft.mount
After=var-lib-certweft.mount
'''

def publish(r):
    text=json.dumps(r,indent=2);OUT.write_text(text);OUT.with_suffix('.html').write_text('<!doctype html><meta charset="utf-8"><pre>'+html.escape(text)+'</pre>')

def mount_unit(options):
    return f'''[Unit]
Description=Disposable Certweft storage fault image
Before=certweft-nginx.service certweft.service certweft-reboot-observe.service
[Mount]
What={LAB}/state.img
Where=/var/lib/certweft
Type=ext4
Options=loop,{options}
[Install]
WantedBy=local-fs.target
'''

def mount_info():
    raw=run(['findmnt','-J','--target',STATE,'-o','TARGET,SOURCE,FSTYPE,OPTIONS']).stdout
    value=json.loads(raw)['filesystems'][0];assert value['target']==str(STATE) and value['fstype']=='ext4'
    value['uuid']=run(['blkid','-s','UUID','-o','value',value['source']]).stdout.decode().strip();assert value['uuid']
    return value

def probe(kind):
    if kind=='sqlite_full':return {'scope':'SQLite fault checked by formal root verifier, not a test SQL substitute'}
    path=STATE/'crossboot-fault-probe'
    try:
        with path.open('wb',buffering=0) as stream:stream.write(b'x'*4096);os.fsync(stream.fileno())
    except OSError as e:
        assert e.errno=={'enospc':errno.ENOSPC,'readonly':errno.EROFS}[kind],e
        return {'errno':e.errno,'real_filesystem_probe_failed':True}
    else:raise AssertionError('fault_not_active')
    finally:
        if path.exists():path.unlink()

def stop():
    run(['systemctl','stop','certweft.service']);assert_empty('certweft.service');run(['systemctl','stop','certweft-nginx.service']);assert_empty('certweft-nginx.service')

def unavailable_or_closed(kind,identity):
    # A full/RO filesystem can prevent lease/Gate startup before any socket exists.
    # Do not manufacture a successful Gate transition from service unavailability.
    if kind in {'enospc','readonly'}:
        end=time.monotonic()+12
        while time.monotonic()<end:
            p=props('certweft.service')
            if p['ActiveState']=='failed' and p['MainPID']=='0':break
            time.sleep(.05)
        assert p['ActiveState']=='failed' and p['MainPID']=='0',p
        result,r=cli('gate',ok=False);assert r.returncode and not result['ok']
        root,rr=cli('recover','--prefix',identity,ok=False);assert rr.returncode and not root['ok']
        return {'mode':'management_unavailable','systemd':p,'gate_cli':result,'root_cli':root,'gate_write_not_claimed':True}
    gate,p=wait_ready();assert not gate['gate_allows_updates']
    current=cli('status')[0]['result'];cert=pathlib.Path((LAB/'candidate-path').read_text())
    denied,r=cli('submit','--certificate',cert,'--request-id','closed-'+identity,'--epoch',current['epoch'],'--revision',current['revision'],user='certweft-operator',ok=False)
    assert r.returncode and denied['reason']=='recovery_required',denied
    failed,rr=cli('recover','--prefix',identity,ok=False,timeout=60);assert rr.returncode and failed['reason']=='recovery_step_FAILED',failed
    history=cli('recovery-request-status','--request-id',identity+'-cert')[0]['result']
    assert history['state']=='FAILED' and history['result']['sqlite_error']=='SQLITE_FULL' and not history['result'].get('restored') and not history['result'].get('updates_enabled'),history
    after=cli('gate')[0];assert not after['gate_allows_updates']
    return {'mode':'closed_management','before':gate,'new_update_denied':denied,'root_cli':failed,'root_failed_history':history,'after':after,'runtime':runtime_identity(p,DROP)}

def prepare(kind):
    assert kind in {'enospc','readonly','sqlite_full'} and not LAB.exists(),'existing_lab_requires_inspection'
    if kind=='enospc':
        if OUT.exists():
            archive=P/'evidence/storage-reboot-attempts';archive.mkdir(exist_ok=True);(archive/(str(time.time_ns())+'.json')).write_bytes(OUT.read_bytes())
        report={'passed':False,'status':'in_progress','source_sha256':hashes(),'cases':[],'scope':'installed services; dedicated ext4 image; normal guest poweroff/start; explicit root repair/recovery','untested':['physical medium failures','sudden power loss','boot zero-gap','unbounded stability']};publish(report)
    report=json.loads(OUT.read_text());assert report['source_sha256']==hashes()
    assert not pathlib.Path('/etc/systemd/system',MOUNT).exists() and not pathlib.Path('/etc/systemd/system',OBUNIT).exists()
    assert not pathlib.Path('/etc/systemd/system/certweft.service.d').exists()
    stop();LAB.mkdir(mode=0o700);(LAB/'owner.json').write_text(json.dumps({'scope':'disposable-certweft-storage-reboot','kind':kind}))
    config=pathlib.Path('/etc/certweft/writer.json');original=json.loads(config.read_text());(LAB/'original-config.json').write_text(json.dumps(original))
    image=LAB/'state.img'
    with image.open('xb') as stream:stream.truncate(32*1024*1024)
    run(['mkfs.ext4','-q','-F','-m','0',image]);stage=LAB/'stage';stage.mkdir();run(['mount','-o','loop',image,stage])
    try:shutil.copytree(STATE,stage,dirs_exist_ok=True,symlinks=True)
    finally:run(['umount',stage])
    STATE.rename(LAB/'original-state');STATE.mkdir(mode=0o700)
    path=pathlib.Path('/etc/systemd/system',MOUNT);path.write_text(mount_unit('rw'));run(['systemctl','daemon-reload']);run(['systemctl','enable','--now',MOUNT]);mounted=mount_info()
    if kind=='sqlite_full':
        with contextlib.closing(sqlite3.connect(STATE/'journal.db')) as db, db:
            db.execute('CREATE TABLE crossboot_pressure(data BLOB)')
            db.execute("CREATE TRIGGER crossboot_commit BEFORE UPDATE ON requests WHEN NEW.state='COMMITTED' BEGIN INSERT INTO crossboot_pressure VALUES(zeroblob(1048576)); END")
            db.execute('CREATE TRIGGER crossboot_probe BEFORE UPDATE ON storage_probe BEGIN INSERT INTO crossboot_pressure VALUES(zeroblob(1048576)); END')
            limit=db.execute('PRAGMA page_count').fetchone()[0]+2
        original={**original,'sqlite_max_pages':limit}
    # The marker directory must be writable from the fixed writer namespace.
    marker=STATE/'crossboot-marker.json';config.write_text(json.dumps({**original,'pause_at':'confirmed','marker':str(marker)}))
    run(['systemctl','start','certweft.service']);gate,p=wait_ready();assert gate['gate_allows_updates']
    core=cli('status')[0]['result'];candidate,candidate_leaf=public_alternative('storage-'+kind,core['committed']);(LAB/'candidate-path').write_text(str(candidate))
    cli('submit','--certificate',candidate,'--request-id','pending-'+kind,'--epoch',core['epoch'],'--revision',core['revision'],user='certweft-operator')
    end=time.monotonic()+4
    while not marker.exists() and time.monotonic()<end:time.sleep(.02)
    assert marker.exists() and wire()==candidate_leaf and snapshot()['state']['state']=='APPLYING'
    # Preserve the uncommitted candidate across application shutdown; do not let
    # SIGTERM rollback create the state later attributed to boot recovery.
    fd=os.pidfd_open(int(p['MainPID']))
    try:signal.pidfd_send_signal(fd,signal.SIGSTOP)
    finally:os.close(fd)
    stop();config.write_text(json.dumps(original))
    if kind=='readonly':
        run(['systemctl','stop',MOUNT]);path.write_text(mount_unit('ro'));run(['systemctl','daemon-reload']);run(['systemctl','start',MOUNT])
    elif kind=='enospc':
        with (STATE/'crossboot-filler').open('xb',buffering=0) as stream:
            try:
                while True:stream.write(b'x'*65536)
            except OSError as e:assert e.errno==errno.ENOSPC
            os.fsync(stream.fileno())
        with (STATE/'crossboot-last-blocks').open('xb',buffering=0) as stream:
            try:
                while True:stream.write(b'x'*4096)
            except OSError as e:assert e.errno==errno.ENOSPC
            os.fsync(stream.fileno())
    fault=probe(kind)
    # Observer is the exact existing read-only journal observer, with only its
    # private plan/output directory relocated. Mount precedes both target units.
    observer=OBSERVER.replace('/var/lib/certweft-reboot-lab',str(LAB));(LAB/'observe.py').write_text(observer)
    unit=UNIT.replace('/var/lib/certweft-reboot-lab',str(LAB)).replace('[Unit]\n','[Unit]\nRequires=var-lib-certweft.mount\nAfter=var-lib-certweft.mount\n',1)
    pathlib.Path('/etc/systemd/system',OBUNIT).write_text(unit)
    drop=pathlib.Path('/etc/systemd/system/certweft.service.d');drop.mkdir();(drop/'reboot-evidence.conf').write_text(DROP)
    # Prime the observer for this boot’s explicit failed startup attempt.
    # This synthetic preflight boot ID is not reboot evidence. Replace its output
    # and plan with the actual boot pair before the host powers the VM off.
    config_plan={'case':kind,'boot_id':'fixture-preboot','before':json.loads(json.dumps(snapshot()))}
    (LAB/'plan.json').write_text(json.dumps(config_plan));run(['systemctl','daemon-reload']);reset()
    run(['systemctl','start','certweft.service'],ok=False)
    pre=unavailable_or_closed(kind,'blocked-before-'+kind);assert wire()==candidate_leaf
    stop();run(['systemctl','stop',OBUNIT]);(LAB/('observed-'+kind+'.json')).unlink()
    before=json.loads(json.dumps(snapshot()));assert before['state']['committed']==core['committed']
    assert not any(row[0]=='pending-'+kind and row[1]=='COMMITTED' for row in before['requests'])
    plan={'case':kind,'boot_id':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'before':before,'old_core':core,'candidate_leaf':candidate_leaf,'committed_leaf':expected(core['committed']),'mount_uuid':mounted['uuid'],'fault_before':fault,'failed_start_before_reboot':pre}
    (LAB/'plan.json').write_text(json.dumps(plan));run(['systemctl','enable','certweft.service']);report['pending_case']=kind;publish(report)
    print(json.dumps({'prepared':kind,'passed':True}))

def check(kind):
    report=json.loads(OUT.read_text());plan=json.loads((LAB/'plan.json').read_text());assert plan['case']==kind and report['source_sha256']==hashes()
    obs=json.loads((LAB/('observed-'+kind+'.json')).read_text());boot=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    from tools.reboot_vm import boot_pair
    boot_pair(plan,obs,boot);mount=mount_info();assert mount['uuid']==plan['mount_uuid']
    actual_fault=probe(kind);blocked=unavailable_or_closed(kind,'blocked-after-'+kind);assert wire()==plan['candidate_leaf']
    assert not any(row[0]=='pending-'+kind and row[1]=='COMMITTED' for row in snapshot()['requests'])
    # The once-per-boot observer has now been checked against this boot. Detach
    # its test-only dependency before stopping the mount for repair; stopping a
    # required mount also stops its dependent observer. Keep its O_EXCL evidence.
    pathlib.Path('/etc/systemd/system/certweft.service.d/reboot-evidence.conf').write_text(REPAIR_DROP)
    run(['systemctl','daemon-reload']);run(['systemctl','stop',OBUNIT])
    # Repair only known test pressure/config; no journal/Gate/history deletion.
    stop()
    mount_path=pathlib.Path('/etc/systemd/system',MOUNT)
    if kind=='readonly':
        run(['systemctl','stop',MOUNT]);mount_path.write_text(mount_unit('rw'));run(['systemctl','daemon-reload']);run(['systemctl','start',MOUNT])
    if kind=='enospc':
        (STATE/'crossboot-filler').unlink();(STATE/'crossboot-last-blocks').unlink()
    if kind=='sqlite_full':
        with contextlib.closing(sqlite3.connect(STATE/'journal.db')) as db, db:
            db.execute('DROP TRIGGER crossboot_commit');db.execute('DROP TRIGGER crossboot_probe');db.execute('DROP TABLE crossboot_pressure')
        config=pathlib.Path('/etc/certweft/writer.json');cfg=json.loads(config.read_text());cfg.pop('sqlite_max_pages');config.write_text(json.dumps(cfg))
    reset();run(['systemctl','start','certweft.service']);closed,p=wait_ready();assert not closed['gate_allows_updates'] and wire()==plan['candidate_leaf']
    runtime=runtime_identity(p,REPAIR_DROP)
    opened,_=cli('recover','--prefix','fixed-'+kind,timeout=65);assert opened['updates_enabled'];restored=wire();assert restored==plan['committed_leaf']
    root_rows=[cli('recovery-request-status','--request-id',i)[0]['result'] for i in opened['requests']]
    pending_history=cli('request-status','--request-id','pending-'+kind)[0]['result'];assert pending_history['state']=='INTERRUPTED'
    core=cli('status')[0]['result'];cert=pathlib.Path((LAB/'candidate-path').read_text())
    old,_=cli('submit','--certificate',cert,'--request-id','stale-'+kind,'--epoch',plan['old_core']['epoch'],'--revision',plan['old_core']['revision'],'--wait',user='certweft-operator',ok=False)
    assert old['reason']=='activation_FAILED';history=cli('request-status','--request-id','stale-'+kind)[0]['result'];assert snapshot()['state']==core and wire()==restored
    fresh,_=cli('submit','--certificate',cert,'--request-id','fresh-'+kind,'--epoch',core['epoch'],'--revision',core['revision'],'--wait',user='certweft-operator');changed=wire();activation_control(history,fresh,restored,changed,plan['candidate_leaf'])
    if kind=='sqlite_full':
        old_root,rr=cli('recover','--prefix','blocked-before-'+kind,ok=False);assert rr.returncode and not old_root['ok']
    detail={'name':kind,'passed':True,'old_boot_id':plan['boot_id'],'current_boot_id':boot,'before_shutdown':plan['before'],'before_writer_on_new_boot':obs,'mount_before_uuid':plan['mount_uuid'],'mount_after':mount,'fault_before':plan['fault_before'],'fault_after':actual_fault,'failed_start_before_reboot':plan['failed_start_before_reboot'],'blocked_after_reboot':blocked,'candidate_leaf_while_faulted':plan['candidate_leaf'],'observer_detached_only_after_boot_evidence_verified':True,'closed_after_storage_repair':closed,'writer_runtime_after_repair':runtime,'root_recovery':opened,'root_history':root_rows,'old_pending_history_after_reconciliation':pending_history,'restored_committed_leaf':restored,'stale_response':old,'stale_history':history,'fresh_activation':fresh,'fresh_wire_leaf':changed}
    report['cases'].append(detail);report.pop('pending_case',None);publish(report)
    print(json.dumps({'checked':kind,'passed':True}))

def cleanup(kind):
    report=json.loads(OUT.read_text());assert report['cases'][-1]['name']==kind
    assert json.loads((LAB/'owner.json').read_text())=={'scope':'disposable-certweft-storage-reboot','kind':kind}
    stop();run(['systemctl','disable','certweft.service']);run(['systemctl','stop',OBUNIT]);run(['systemctl','disable','--now',MOUNT]);assert not os.path.ismount(STATE)
    shutil.rmtree(STATE);(LAB/'original-state').rename(STATE)
    pathlib.Path('/etc/certweft/writer.json').write_text((LAB/'original-config.json').read_text())
    d=pathlib.Path('/etc/systemd/system/certweft.service.d');(d/'reboot-evidence.conf').unlink();d.rmdir()
    for unit in [MOUNT,OBUNIT]:pathlib.Path('/etc/systemd/system',unit).unlink()
    image=str(LAB/'state.img');assert not run(['losetup','-j',image]).stdout.strip(),'loop_leaked'
    run(['systemctl','daemon-reload']);shutil.rmtree(LAB)
    report['cases'][-1]['cleanup']={'services_empty':{u:assert_empty(u) for u in ['certweft.service','certweft-nginx.service']},'image_unmounted_loop_detached':True,'temporary_units_removed':True,'original_state_restored_for_fixture_reset':True}
    report.update(source_unchanged=report['source_sha256']==hashes());report['passed']=report['source_unchanged'] and [c['name'] for c in report['cases']]==['enospc','readonly','sqlite_full'];report['status']='completed' if report['passed'] else 'in_progress';publish(report)
    print(json.dumps({'cleaned':kind,'passed':True,'all_completed':report['passed']}))

if __name__=='__main__':
    if os.geteuid()!=0 or os.environ.get('CERTWEFT_STORAGE_REBOOT_VM')!='1':raise PermissionError('explicit disposable Linux VM required')
    os.umask(0o077)
    try:globals()[sys.argv[1]](sys.argv[2])
    except Exception as e:
        if OUT.exists():
            r=json.loads(OUT.read_text());r.update(passed=False,status='failed',error=type(e).__name__+':'+str(e));publish(r)
        raise
