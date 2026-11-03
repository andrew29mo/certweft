"""Three installed storage-fault normal VM reboot/repair cycles; explicit profile."""
import argparse,hashlib,html,json,pathlib,re,shlex,sys,time
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
from tools.reboot_host import command,checked,state
P=pathlib.Path(__file__).resolve().parents[1]

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--profile',required=True);profile=ap.parse_args().profile
    assert re.fullmatch('[a-z0-9][a-z0-9-]{0,50}',profile) and profile!='default'
    context=checked(['docker','context','show']).stdout.strip();assert context and state(profile)=='Running'
    ssh=['colima','-p',profile,'ssh','--'];checked(ssh+['sudo','test','!','-e','/var/lib/certweft-storage-reboot-lab'])
    out=P/'evidence/storage-reboot-host.json';report={'passed':False,'status':'in_progress','profile':profile,'cycles':[],'scope':'guest poweroff/start while dedicated state image remains full/RO/SQLite-quota limited; no physical power loss'}
    if out.exists():
        archive=P/'evidence/storage-reboot-attempts';archive.mkdir(exist_ok=True);(archive/(str(time.time_ns())+'-host.json')).write_bytes(out.read_bytes())
    def publish():
        text=json.dumps(report,indent=2);out.write_text(text);out.with_suffix('.html').write_text('<!doctype html><meta charset="utf-8"><pre>'+html.escape(text)+'</pre>')
    def phase(tool,*params):
        flag='CERTWEFT_DEPLOYMENT_VM' if tool=='deployment_vm' else 'CERTWEFT_STORAGE_REBOOT_VM';budget=300 if tool=='deployment_vm' else 110
        script='cd '+shlex.quote(str(P))+' && sudo env '+flag+'=1 PYTHONDONTWRITEBYTECODE=1 timeout '+str(budget)+' python3 tools/'+tool+'.py '+shlex.join(params)
        r=checked(ssh+['sh','-c',script],budget+20)
        return [json.loads(line) for line in r.stdout.splitlines() if line.startswith('{')][-1]
    def boot():
        value=checked(ssh+['cat','/proc/sys/kernel/random/boot_id']).stdout.strip();assert re.fullmatch('[0-9a-f-]{36}',value);return value
    publish()
    try:
        for kind in ['enospc','readonly','sqlite_full']:
            cycle={'fault':kind};report['cycles'].append(cycle);publish()
            cycle['bootstrap']=phase('deployment_vm','--bootstrap-only');assert cycle['bootstrap']['passed']
            assert phase('storage_reboot_vm','prepare',kind)=={'prepared':kind,'passed':True}
            old=boot();cycle['old_boot_id']=old;start=time.monotonic();cycle['poweroff_command']=['sudo','systemctl','poweroff'];publish()
            result=command(ssh+['sudo','systemctl','poweroff'],20);cycle['poweroff_transport_returncode']=result.returncode
            until=time.monotonic()+40
            while state(profile)!='Stopped':
                if time.monotonic()>=until:raise TimeoutError('guest_did_not_stop')
                time.sleep(.5)
            cycle['manager_status_after_poweroff']='Stopped';cycle['poweroff_to_stopped_observed_seconds']=time.monotonic()-start
            checked(['colima','-p',profile,'start'],120);assert state(profile)=='Running'
            new=boot();assert new!=old;cycle['new_boot_id']=new;cycle['manager_status_after_start']='Running';publish()
            started=time.monotonic();assert phase('storage_reboot_vm','check',kind)=={'checked':kind,'passed':True};cycle['post_ssh_check_and_repair_seconds']=time.monotonic()-started
            vm=json.loads((P/'evidence/storage-reboot.json').read_text());entry=vm['cases'][-1]
            assert entry['old_boot_id']==old and entry['current_boot_id']==new and entry['passed']
            done=phase('storage_reboot_vm','cleanup',kind);assert done['cleaned']==kind and done['passed'];cycle['vm_check_and_cleanup_passed']=True;publish()
        vm=json.loads((P/'evidence/storage-reboot.json').read_text());assert vm['passed']
        report.update(passed=True,status='completed',source_sha256=vm['source_sha256'],vm_report_sha256=hashlib.sha256((P/'evidence/storage-reboot.json').read_bytes()).hexdigest())
    except Exception as e:
        report.update(passed=False,status='failed',error=type(e).__name__+':'+str(e));raise
    finally:
        restored=command(['docker','context','use',context]);report['docker_context_restored']=restored.returncode==0 and checked(['docker','context','show']).stdout.strip()==context
        report['passed']=report['passed'] and report['docker_context_restored'];publish()
    print(json.dumps({'passed':report['passed'],'storage_fault_reboots':len(report['cycles'])}));return 0 if report['passed'] else 1
if __name__=='__main__':sys.exit(main())
