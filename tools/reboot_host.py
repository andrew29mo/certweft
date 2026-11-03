"""Drive normal guest poweroff/start and retain sanitized host-side evidence.

Requires an explicitly selected, already running disposable Colima VM provisioned
per INSTALL.md, the source mounted at its host path, and no existing reboot lab.
The deployment fixture may reset its explicitly marked evaluation installation.
"""
import argparse,hashlib,html,json,pathlib,re,shlex,subprocess,sys,time
P=pathlib.Path(__file__).resolve().parents[1]

def command(args,timeout=45):
    return subprocess.run(args,cwd=P,capture_output=True,text=True,timeout=timeout)

def checked(args,timeout=45):
    r=command(args,timeout)
    if r.returncode:raise RuntimeError('command_failed:'+args[0]+':'+str(r.returncode))
    return r

def state(profile):
    rows=[json.loads(line) for line in checked(['colima','list','--json']).stdout.splitlines() if line.strip()]
    found=[r for r in rows if r['name']==profile];assert len(found)==1,'profile_not_found'
    return found[0]['status']

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--profile',required=True);args=parser.parse_args();profile=args.profile
    assert re.fullmatch('[a-z0-9][a-z0-9-]{0,50}',profile) and profile!='default','explicit_nondefault_disposable_profile_required'
    context=checked(['docker','context','show']).stdout.strip();assert context
    assert state(profile)=='Running','start_selected_vm_first'
    ssh=['colima','-p',profile,'ssh','--']
    # Refuse an existing diagnostic lab; do not recursively erase unknown data.
    checked(ssh+['sudo','test','!','-e','/var/lib/certweft-reboot-lab'])
    report={'passed':False,'status':'in_progress','profile':profile,'cycles':[],'scope':'host-driven guest systemctl poweroff, manager Stopped, then same-profile start; no physical power loss'}
    out=P/'evidence/reboot-host.json'
    if out.exists():
        archive=P/'evidence/reboot-attempts';archive.mkdir(exist_ok=True);(archive/(str(time.time_ns())+'-host.json')).write_bytes(out.read_bytes())
    def publish():
        text=json.dumps(report,indent=2);out.write_text(text);out.with_suffix('.html').write_text('<!doctype html><meta charset="utf-8"><pre>'+html.escape(text)+'</pre>')
    def phase(tool,*params):
        flag='CERTWEFT_DEPLOYMENT_VM' if tool=='deployment_vm' else 'CERTWEFT_REBOOT_VM';budget=300 if tool=='deployment_vm' else 100
        script='cd '+shlex.quote(str(P))+' && sudo env '+flag+'=1 PYTHONDONTWRITEBYTECODE=1 timeout '+str(budget)+' python3 tools/'+tool+'.py '+shlex.join(params)
        result=checked(ssh+['sh','-c',script],budget+20)
        return [json.loads(line) for line in result.stdout.splitlines() if line.startswith('{')][-1]
    def boot_id():
        value=checked(ssh+['cat','/proc/sys/kernel/random/boot_id']).stdout.strip();assert re.fullmatch('[0-9a-f-]{36}',value);return value
    publish()
    try:
        report['bootstrap']=phase('deployment_vm','--bootstrap-only');assert report['bootstrap']['passed'];publish()
        for case in ['pending','committed','reopened']:
            prepared=phase('reboot_vm','prepare',case);assert prepared['prepared']==case
            old_boot=boot_id();start=time.monotonic();cycle={'case':case,'old_boot_id':old_boot,'poweroff_command':['sudo','systemctl','poweroff']};report['cycles'].append(cycle);publish()
            # An SSH/Colima error is not success: require manager-confirmed Stopped.
            result=command(ssh+['sudo','systemctl','poweroff'],20);cycle['poweroff_transport_returncode']=result.returncode
            until=time.monotonic()+40
            while state(profile)!='Stopped':
                if time.monotonic()>=until:raise TimeoutError('guest_did_not_stop')
                time.sleep(.5)
            cycle['manager_status_after_poweroff']='Stopped';cycle['poweroff_to_stopped_observed_seconds']=time.monotonic()-start;publish()
            checked(['colima','-p',profile,'start'],120);assert state(profile)=='Running'
            new_boot=boot_id();assert new_boot!=old_boot;cycle['new_boot_id']=new_boot;cycle['manager_status_after_start']='Running'
            checked_case=phase('reboot_vm','check',case);assert checked_case=={'checked':case,'passed':True}
            vm=json.loads((P/'evidence/reboot.json').read_text());entry=vm['cases'][-1]
            assert entry['old_boot_id']==old_boot and entry['current_boot_id']==new_boot,'host_vm_boot_pair_mismatch'
            cycle['vm_check_passed']=True;publish()
        report['finish']=phase('reboot_vm','finish');assert report['finish']['passed']
        vm=json.loads((P/'evidence/reboot.json').read_text());assert vm['passed'];report['source_sha256']=vm['source_sha256'];report['vm_report_sha256']=hashlib.sha256((P/'evidence/reboot.json').read_bytes()).hexdigest()
        report.update(passed=True,status='completed')
    except Exception as error:
        report.update(passed=False,status='failed',error=type(error).__name__+':'+str(error));raise
    finally:
        restored=command(['docker','context','use',context]);report['docker_context_restored']=restored.returncode==0 and checked(['docker','context','show']).stdout.strip()==context
        report['passed']=report['passed'] and report['docker_context_restored'];publish()
    print(json.dumps({'passed':report['passed'],'normal_vm_cycles':len(report['cycles'])}));return 0 if report['passed'] else 1

if __name__=='__main__':sys.exit(main())
