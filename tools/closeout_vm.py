"""Installed-service capacity and 1200-second bounded resource qualification."""
import contextlib,hashlib,html,json,math,os,pathlib,signal,sqlite3,statistics,sys,time
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
from tools.deployment_vm import run,cli,props,wait_ready,kill_main,assert_empty,reset,memory,P
from tools.executor_vm import hashes
from tools.reboot_vm import wire,expected,public_alternative,payload
from tools.storage_reboot_vm import catalogs,preserve_history,root_call
STATE=pathlib.Path('/var/lib/certweft');PY='/opt/certweft/bin/python'

def save(path,report):
    text=json.dumps(report,indent=2);path.write_text(text);path.with_suffix('.html').write_text('<!doctype html><meta charset="utf-8"><pre>'+html.escape(text)+'</pre>')

def counts():
    c=catalogs();return {'normal':len(c['normal']),'root':len(c['root']),'generations':len(list(STATE.glob('v-*')))}

def stable():return {'core':cli('status')[0]['result'],'leaf':wire(),'catalogs':catalogs(),'counts':counts()}

def stop():
    run(['systemctl','stop','certweft.service']);run(['systemctl','stop','certweft-nginx.service'])
    return {u:assert_empty(u) for u in ['certweft.service','certweft-nginx.service']}

def start():
    reset();run(['systemctl','start','certweft.service']);gate,p=wait_ready();payload()
    args=pathlib.Path('/proc',p['MainPID'],'cmdline').read_bytes().rstrip(b'\0').decode().split('\0')
    assert args==[PY,'-I','-m','certweft.service','/etc/certweft/writer.json'] and os.readlink('/proc/'+p['MainPID']+'/cwd')=='/'
    assert pathlib.Path('/etc/systemd/system/certweft.service').read_bytes()==(pathlib.Path(payload()['installed_root'])/'certweft/assets/certweft.service').read_bytes()
    assert not pathlib.Path('/etc/systemd/system/certweft.service.d').exists()
    m=memory(int(p['MainPID']));assert int(m['CapEff'],16)==1 and m['NoNewPrivs']=='1' and m['Uid'].split()==['0']*4
    return gate,p

def submit(identity,cert,core,wait=True,ok=True):
    args=['submit','--certificate',cert,'--request-id',identity,'--epoch',core['epoch'],'--revision',core['revision']]
    if wait:args.append('--wait')
    return cli(*args,user='certweft-operator',ok=ok)[0]

def wait_job(identity):
    end=time.monotonic()+15
    while time.monotonic()<end:
        row=cli('request-status','--request-id',identity)[0]['result']
        if row['state'] not in {'ACCEPTED','RUNNING','CANCEL_REQUESTED'} and not cli('gate')[0]['executor_busy']:return row
        time.sleep(.03)
    raise TimeoutError('job_not_terminal')

def root_wait(identity):
    end=time.monotonic()+15
    while time.monotonic()<end:
        row=cli('recovery-request-status','--request-id',identity)[0]['result']
        if row['state'] not in {'ACCEPTED','RUNNING','CERTIFICATE_VERIFIED'} and not cli('gate')[0]['executor_busy']:return row
        time.sleep(.03)
    raise TimeoutError('root_job_not_terminal')

def prepare_root():
    gate=cli('gate')[0]['gate']
    if gate['state']=='RECOVERY_REQUIRED':root_call({'op':'prepare-recovery','gate_epoch':gate['epoch'],'gate_revision':gate['revision']})
    gate=cli('gate')[0]['gate'];assert gate['state']=='VERIFY_REQUIRED';return gate

def verify_body(identity):
    gate=cli('gate')[0]['gate'];return {'op':'verify-storage','request_id':identity,'timeout_seconds':10,'gate_epoch':gate['epoch'],'gate_revision':gate['revision']}

def fill_root(n):
    records=[]
    for i in range(n):
        body=verify_body('fill-root-'+str(i));r=root_call(body);assert r['ok']
        row=root_wait(body['request_id']);assert row['state']=='STORAGE_VERIFIED' and not row['result']['updates_enabled']
        records.append({'body':body,'row':row})
    return records

def dirty_pending(label):
    config=pathlib.Path('/etc/certweft/writer.json');original=json.loads(config.read_text());marker=STATE/'closeout-marker.json'
    config.write_text(json.dumps({**original,'pause_at':'confirmed','marker':str(marker)}));gate,p=start();assert gate['gate_allows_updates']
    core=cli('status')[0]['result'];cert,leaf=public_alternative(label,core['committed']);submit('pending-'+label,cert,core,False)
    end=time.monotonic()+4
    while not marker.exists() and time.monotonic()<end:time.sleep(.02)
    assert marker.exists() and wire()==leaf
    config.write_text(json.dumps(original));kill_main(p);gate,new=wait_ready(p['InvocationID']);assert not gate['gate_allows_updates']
    assert new['InvocationID']!=p['InvocationID'];prepare_root();return cert,core,leaf

def normal_capacity():
    gate,p=start();assert gate['gate_allows_updates'];core=cli('status')[0]['result'];cert,_=public_alternative('normal-capacity',core['committed']);stale={**core,'revision':core['revision']-1};first=None
    for i in range(63):
        response=submit('history-'+str(i),cert,stale,ok=False);assert response['reason']=='activation_FAILED'
        row=wait_job('history-'+str(i));assert row['state']=='FAILED' and row['result']['error']=='Rejected'
        if first is None:first=row
    before=stable();assert before['counts']=={'normal':64,'root':0,'generations':2}
    full=submit('history-over',cert,core,False,False);assert full['reason']=='history_full';assert stable()==before
    dup=submit('history-0',cert,stale,False);assert not dup['created'] and dup['result']==first
    conflict=submit('history-0',cert,core,False,False);assert conflict['reason']=='request_conflict';assert stable()==before
    first_restart=retained_restart();gate=first_restart['gate_after'];p=props('certweft.service');assert counts()['normal']==64
    again=submit('history-after-restart',cert,core,False,False);assert again['reason']=='history_full'
    kill_main(p);gate,_=wait_ready(p['InvocationID']);assert not gate['gate_allows_updates']
    reopened,_=cli('recover','--prefix','normal-full-repair',timeout=65);assert reopened['updates_enabled'] and counts()['normal']==64
    assert submit('history-after-recovery',cert,cli('status')[0]['result'],False,False)['reason']=='history_full'
    preserve_history(before['catalogs'],catalogs())
    return {'actual_requests_to_64':True,'independent_counts_before':before['counts'],'overflow':full,'same_body_replay':dup,'changed_body':conflict,'first_restart':first_restart,'restart_overflow':again,'root_recovery_despite_normal_full':reopened,'final_counts':counts()}

def generation_capacity():
    gate,p=start();assert gate['gate_allows_updates'];updates=[]
    for i in range(14):
        core=cli('status')[0]['result'];cert,target=public_alternative('version-'+str(i),core['committed']);old=wire();r=submit('version-'+str(i),cert,core);assert r['result']['state']=='COMMITTED' and wire()==target!=old;updates.append({'id':'version-'+str(i),'leaf':target})
    before=stable();assert before['counts']=={'normal':15,'root':0,'generations':16}
    core=before['core'];cert,target=public_alternative('version-over',core['committed']);r=submit('version-over',cert,core,ok=False);assert r['reason']=='activation_FAILED';row=wait_job('version-over');assert row['state']=='FAILED' and row['result']['error']=='Rejected'
    assert counts()['generations']==16 and wire()==before['leaf'] and cli('status')[0]['result']==core;preserve_history(before['catalogs'],catalogs())
    first_restart=retained_restart();assert counts()['generations']==16
    after=submit('version-after-restart',cert,core,ok=False);assert after['reason']=='activation_FAILED' and wire()==before['leaf'] and counts()['generations']==16
    return {'actual_successful_updates':updates,'independent_counts_before':before['counts'],'overflow_response':r,'overflow_history':row,'first_restart':first_restart,'restart_response':after,'core_and_leaf_preserved':True,'final_counts':counts(),'diagnostic_limit':'executor API exposes Rejected class, not a version_capacity reason; exact backend branch additionally unit-tested'}

def root_capacity():
    gate,p=start();kill_main(p);wait_ready(p['InvocationID']);prepare_root();filled=fill_root(16);before=stable();assert before['counts']=={'normal':1,'root':16,'generations':2}
    full=root_call(verify_body('root-over'));assert full=={'ok':False,'reason':'recovery_history_full'};assert stable()==before
    duplicate=root_call(filled[0]['body']);assert duplicate['ok'] and not duplicate['created'] and duplicate['historical'] and duplicate['result']==filled[0]['row']
    bad=root_call({**filled[0]['body'],'timeout_seconds':9});assert bad['reason']=='request_conflict';assert stable()==before
    first_restart=retained_restart();prepare_root();again=root_call(verify_body('root-after-restart'));assert again['reason']=='recovery_history_full';assert counts()['root']==16;preserve_history(before['catalogs'],catalogs())
    return {'actual_verifications_to_16':filled,'independent_counts_before':before['counts'],'overflow':full,'replay':duplicate,'conflict':bad,'first_restart':first_restart,'restart_overflow':again,'final_counts':counts(),'gate_still_closed':not cli('gate')[0]['gate_allows_updates']}

def limited_root(remaining):
    cert,old,candidate=dirty_pending('remaining-'+str(remaining));filled=fill_root(16-remaining);before=catalogs();r,rc=cli('recover','--prefix','limited',ok=remaining==5,timeout=65)
    states=['VERIFIED_CLOSED','JOURNAL_VERIFIED_CLOSED','OPENING_VERIFIED_CLOSED','RELEASE_VERIFIED_CLOSED','OPENED'];ids=['cert','journal','intent','release','open'];actual=[cli('recovery-request-status','--request-id','limited-'+s)[0]['result'] for s in ids[:remaining]]
    assert [x['state'] for x in actual]==states[:remaining] and counts()['root']==16
    gate=cli('gate')[0];core=cli('status')[0]['result']
    if remaining<5:
        assert rc.returncode and r['reason']=='recovery_history_full' and not gate['gate_allows_updates']
        denied=submit('limited-denied',cert,core,False,False);assert denied['reason']=='stale_gate_authority'
        assert wire()==(candidate if remaining==0 else expected(old['committed']))
    else:
        assert r['updates_enabled'] and gate['gate_allows_updates'];assert wire()==expected(old['committed'])
        active=submit('after-limited-full',cert,core);assert active['result']['state']=='COMMITTED' and wire()==candidate;denied=None
    preserve_history(before,catalogs());saved=counts();first_restart=retained_restart();assert counts()==saved and not cli('gate')[0]['gate_allows_updates'];preserve_history(before,catalogs())
    return {'remaining_before':remaining,'fill_count':len(filled),'recover_response':r,'completed_steps':actual,'post_operation_gate':gate,'denied_while_partial':denied,'root_rows_after':16,'first_restart':first_restart,'restart_closed_and_counts_preserved':True,'partial_progress_not_rolled_back':True}

def retained_restart():
    before=stable();old=props('certweft.service');stop();gate,new=start();after=stable()
    assert old['InvocationID']!=new['InvocationID'],'service_not_restarted'
    assert before==after,'full_state_or_history_changed_on_restart'
    return {'before':before,'after':after,'old_invocation':old['InvocationID'],'new_invocation':new['InvocationID'],'gate_after':gate,'full_catalog_core_wire_counts_equal':True}

def capacity(case):
    out=P/'evidence/capacity.json'
    if case=='normal':
        if out.exists():
            d=P/'evidence/closeout-attempts';d.mkdir(exist_ok=True);(d/(str(time.time_ns())+'-capacity.json')).write_bytes(out.read_bytes())
        save(out,{'passed':False,'status':'in_progress','source_sha256':hashes(),'cases':[],'scope':'actual installed CLI/systemd lifecycle, no seeded history or fabricated generation directories'})
    report=json.loads(out.read_text());assert report['source_sha256']==hashes();start_time=time.monotonic()
    try:
        if case=='normal':detail=normal_capacity()
        elif case=='generations':detail=generation_capacity()
        elif case=='root':detail=root_capacity()
        else:detail=limited_root(int(case.split('-')[1]))
        detail['full_catalog_restart']=retained_restart()
        cleanup=stop();report['cases'].append({'name':case,'passed':True,'elapsed_seconds':time.monotonic()-start_time,'detail':detail,'cleanup':cleanup})
        names=['normal','generations','root']+['remaining-'+str(n) for n in range(6)]
        report['passed']=[c['name'] for c in report['cases']]==names and report['source_sha256']==hashes();report['status']='completed' if report['passed'] else 'in_progress'
    except Exception as e:report.update(passed=False,status='failed',error=type(e).__name__+':'+str(e));raise
    finally:save(out,report)
    print(json.dumps({'case':case,'passed':True,'all_completed':report['passed']}))

def proc_metrics(p):
    pid=int(p['MainPID']);v=memory(pid);pids=list(map(int,(pathlib.Path('/sys/fs/cgroup'+p['ControlGroup'])/'cgroup.procs').read_text().split()));group=[]
    for child in pids:
        try:group.append({'pid':child,'rss_kib':int(memory(child)['VmRSS'].split()[0]),'fds':len(list(pathlib.Path('/proc',str(child),'fd').iterdir()))})
        except FileNotFoundError:pass # a retired Nginx worker may exit between reads
    return {'pid':pid,'invocation':p['InvocationID'],'rss_kib':int(v['VmRSS'].split()[0]),'hwm_kib':int(v['VmHWM'].split()[0]),'fds':len(list(pathlib.Path('/proc',str(pid),'fd').iterdir())),'cgroup_pids':pids,'cgroup_samples':group,'cgroup_rss_kib':sum(v['rss_kib'] for v in group),'cgroup_fds':sum(v['fds'] for v in group),'nrestarts':int(p['NRestarts'])}

def disk_metrics():
    inodes={}
    for path in STATE.rglob('*'):
        if path.is_file() and not path.is_symlink():
            s=path.stat();inodes[(s.st_dev,s.st_ino)]=s
    return {'logical_bytes':sum(s.st_size for s in inodes.values()),'allocated_bytes':sum(s.st_blocks*512 for s in inodes.values()),'files':len(inodes),'counts':counts()}

def resource_checks(samples):
    stable_samples=[s for s in samples if s['elapsed_seconds']>=180]
    assert len(stable_samples)>=100,'insufficient_stable_samples'
    rss=[s['writer']['rss_kib'] for s in stable_samples];x=[s['elapsed_seconds'] for s in stable_samples];meanx=statistics.mean(x);meany=statistics.mean(rss)
    slope=sum((a-meanx)*(b-meany) for a,b in zip(x,rss))/sum((a-meanx)**2 for a in x);growth=slope*(x[-1]-x[0]);delta=statistics.median(rss[-6:])-statistics.median(rss[:6])
    assert max(rss)-min(rss)<=4096 and growth<=1024 and delta<=1024,'writer_rss_growth_exceeded'
    fds=[s['writer']['fds'] for s in stable_samples];assert max(fds)-min(fds)<=2 and max(fds)<=stable_samples[0]['writer']['fds']+2,'writer_fd_growth'
    assert all(len(s['writer']['cgroup_pids'])==1 and s['writer']['nrestarts']==0 for s in samples),'writer_process_leak_or_restart'
    assert all(s['disk']==stable_samples[0]['disk'] for s in stable_samples),'persistent_state_grew_after_warmup'
    assert len({tuple(sorted(s['nginx']['cgroup_pids'])) for s in stable_samples})==1,'nginx_worker_replaced_after_warmup'
    ng=[s['nginx']['cgroup_rss_kib'] for s in stable_samples];ngfds=[s['nginx']['cgroup_fds'] for s in stable_samples]
    assert all(len(s['nginx']['cgroup_pids'])==2 and len(s['nginx']['cgroup_samples'])==2 and s['nginx']['nrestarts']==0 for s in stable_samples),'nginx_process_leak_or_restart'
    assert max(ng)-min(ng)<=4096 and statistics.median(ng[-6:])-statistics.median(ng[:6])<=1024 and max(ngfds)-min(ngfds)<=2,'nginx_resource_growth'
    return {'stable_nginx_pid_sets':1,'nginx_rss_span_kib':max(ng)-min(ng),'nginx_fd_min':min(ngfds),'nginx_fd_max':max(ngfds),'stable_samples':len(stable_samples),'rss_span_kib':max(rss)-min(rss),'rss_fitted_growth_kib':growth,'rss_first_last_median_delta_kib':delta,'fd_min':min(fds),'fd_max':max(fds),'persistent_state_constant_after_180_seconds':True}

def soak():
    out=P/'evidence/soak.json'
    if out.exists():
        d=P/'evidence/closeout-attempts';d.mkdir(exist_ok=True);(d/(str(time.time_ns())+'-soak.json')).write_bytes(out.read_bytes())
    r={'passed':False,'status':'in_progress','source_sha256':hashes(),'duration_seconds':1200,'warmup_seconds':180,'sample_interval_seconds':10,'thresholds_predeclared':{'writer_rss_span_kib':4096,'writer_rss_fitted_growth_kib':1024,'writer_rss_median_growth_kib':1024,'writer_fd_span':2,'quiescent_writer_processes':1,'restarts':0,'stable_disk_growth_bytes':0,'stable_nginx_processes':2,'stable_nginx_pid_sets':1,'nginx_cgroup_rss_span_kib':4096,'nginx_cgroup_rss_median_growth_kib':1024,'nginx_cgroup_fd_span':2},'samples':[],'events':[],'steady_cycles':[],'scope':'single installed writer invocation for 1200 seconds, bounded scripted load; no unbounded stability or leak-free claim'};save(out,r)
    config=pathlib.Path('/etc/certweft/writer.json');original=json.loads(config.read_text());config.write_text(json.dumps({**original,'delay_at':'confirmed','delay_seconds':1.0}));gate,p=start();assert gate['gate_allows_updates'];initial=p;old_ng=props('certweft-nginx.service');replays=[];begin=time.monotonic()
    try:
        for tick in range(121):
            deadline=begin+tick*10
            if time.monotonic()<deadline:time.sleep(deadline-time.monotonic())
            if tick<14:
                core=cli('status')[0]['result'];cert,target=public_alternative('soak-'+str(tick),core['committed']);identity='soak-'+str(tick);bodycore=core
                if tick<8:
                    response=submit(identity,cert,core);assert response['result']['state']=='COMMITTED' and wire()==target;state='COMMITTED'
                elif tick<10:
                    before=wire();submit(identity,cert,core,False)
                    until=time.monotonic()+2
                    while cli('request-status','--request-id',identity)[0]['result']['state']=='ACCEPTED' and time.monotonic()<until:time.sleep(.01)
                    cancel,_=cli('cancel','--request-id',identity,user='certweft-operator');assert cancel['cancel_accepted'];row=wait_job(identity);assert row['state']=='ROLLED_BACK' and wire()==before;response={'cancel':cancel,'row':row};state='ROLLED_BACK'
                else:
                    bodycore={**core,'revision':core['revision']-1};response=submit(identity,cert,bodycore,ok=False);assert response['reason']=='activation_FAILED';row=wait_job(identity);assert row['state']=='FAILED';state='FAILED'
                replays.append((identity,cert,bodycore,state));r['events'].append({'tick':tick,'id':identity,'expected_state':state,'response':response})
                if tick==13:r['history_after_creation']=catalogs()
            elif replays:
                identity,cert,bodycore,state=replays[(tick-14)%len(replays)];duplicate=submit(identity,cert,bodycore,False);assert not duplicate['created'] and duplicate['result']['state']==state
                terminal=cli('request-status','--request-id',identity,user='certweft-operator')[0]['result'];assert terminal['state']==state
                cancel,_=cli('cancel','--request-id',identity,user='certweft-operator');assert not cancel.get('cancel_accepted')
                core=cli('status')[0]['result'];bad=submit('x'*65,cert,core,False,False);assert bad['reason']=='request_id'
                assert catalogs()==r['history_after_creation'],'fixed_history_rewritten_during_soak'
                r['steady_cycles'].append({'tick':tick,'request_id':identity,'duplicate_created':duplicate['created'],'terminal_state':terminal['state'],'terminal_cancel_accepted':cancel.get('cancel_accepted',False),'invalid_new_id_reason':bad['reason'],'full_history_equal':True})
            gate=cli('gate')[0];assert gate['gate_allows_updates'] and not gate['executor_busy'];current=props('certweft.service');ng=props('certweft-nginx.service')
            assert current['MainPID']==initial['MainPID'] and current['InvocationID']==initial['InvocationID'] and ng['MainPID']==old_ng['MainPID'] and ng['InvocationID']==old_ng['InvocationID'],'service_changed_during_soak'
            r['samples'].append({'elapsed_seconds':time.monotonic()-begin,'writer':proc_metrics(current),'nginx':proc_metrics(ng),'disk':disk_metrics(),'wire_leaf':wire()});save(out,r)
        assert r['samples'][-1]['elapsed_seconds']>=1200
        r['history_final']=catalogs();assert r['history_final']==r['history_after_creation'],'fixed_history_rewritten_at_end'
        r['checks']=resource_checks(r['samples']);r['checks']['full_history_constant_after_creation']=True;r.update(passed=True,status='completed',observed_seconds=r['samples'][-1]['elapsed_seconds'],final_counts=counts(),same_writer_invocation=True,same_nginx_master_invocation=True)
    except Exception as e:r.update(passed=False,status='failed',error=type(e).__name__+':'+str(e));raise
    finally:
        try:
            r['cleanup']=stop();r['history_after_stop']=catalogs()
            if 'history_final' in r:assert r['history_after_stop']==r['history_final'],'cleanup_rewrote_history'
        except Exception as e:r.update(passed=False,status='failed',cleanup_error=type(e).__name__+':'+str(e))
        try:config.write_text(json.dumps(original))
        except Exception as e:r.update(passed=False,status='failed',config_restore_error=type(e).__name__+':'+str(e))
        r['source_unchanged']=r['source_sha256']==hashes();r['passed']=r['passed'] and r['source_unchanged']
        if not r['passed']:r['status']='failed'
        save(out,r)
    if not r['passed']:raise AssertionError('soak_failed')
    print(json.dumps({'passed':r['passed'],'samples':len(r['samples']),'observed_seconds':r.get('observed_seconds')}))

if __name__=='__main__':
    if os.geteuid()!=0 or os.environ.get('CERTWEFT_CLOSEOUT_VM')!='1':raise PermissionError('explicit disposable Linux VM required')
    os.umask(0o077)
    if sys.argv[1]=='capacity':capacity(sys.argv[2])
    elif sys.argv[1]=='soak':soak()
    else:raise ValueError('unknown phase')
