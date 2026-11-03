"""Run independent installed capacity fixtures, then one 1200-second invocation."""
import argparse,hashlib,html,json,pathlib,re,shlex,sys,time
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
from tools.reboot_host import command,checked,state
P=pathlib.Path(__file__).resolve().parents[1]

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--profile',required=True);profile=ap.parse_args().profile
    assert re.fullmatch('[a-z0-9][a-z0-9-]{0,50}',profile) and profile!='default' and state(profile)=='Running'
    ssh=['colima','-p',profile,'ssh','--'];context=checked(['docker','context','show']).stdout.strip();assert context
    checked(ssh+['sudo','test','!','-e','/var/lib/certweft-storage-reboot-lab'])
    out=P/'evidence/closeout-host.json';r={'passed':False,'status':'in_progress','capacity_phases':[],'profile':profile,'scope':'fresh marked application installation per capacity case; separate single 1200-second service invocation for resources'}
    if out.exists():
        d=P/'evidence/closeout-attempts';d.mkdir(exist_ok=True);(d/(str(time.time_ns())+'-host.json')).write_bytes(out.read_bytes())
    def save():
        text=json.dumps(r,indent=2);out.write_text(text);out.with_suffix('.html').write_text('<!doctype html><meta charset="utf-8"><pre>'+html.escape(text)+'</pre>')
    def phase(tool,*params):
        flag='CERTWEFT_DEPLOYMENT_VM' if tool=='deployment_vm' else 'CERTWEFT_CLOSEOUT_VM';budget=1320 if params==('soak',) else 300
        script='cd '+shlex.quote(str(P))+' && sudo env '+flag+'=1 PYTHONDONTWRITEBYTECODE=1 timeout '+str(budget)+' python3 tools/'+tool+'.py '+shlex.join(params)
        result=checked(ssh+['sh','-c',script],budget+20)
        return [json.loads(line) for line in result.stdout.splitlines() if line.startswith('{')][-1]
    save()
    try:
        for name in ['normal','generations','root']+['remaining-'+str(n) for n in range(6)]:
            setup=phase('deployment_vm','--bootstrap-only');assert setup['passed']
            result=phase('closeout_vm','capacity',name);assert result['passed'];r['capacity_phases'].append({'name':name,'bootstrap':setup,'result':result});save()
        setup=phase('deployment_vm','--bootstrap-only');assert setup['passed'];r['soak_bootstrap']=setup;save()
        result=phase('closeout_vm','soak');assert result['passed'] and result['observed_seconds']>=1200;r['soak_result']=result
        cap=json.loads((P/'evidence/capacity.json').read_text());soak=json.loads((P/'evidence/soak.json').read_text());assert cap['passed'] and soak['passed'] and cap['source_sha256']==soak['source_sha256']
        r.update(passed=True,status='completed',source_sha256=cap['source_sha256'],capacity_report_sha256=hashlib.sha256((P/'evidence/capacity.json').read_bytes()).hexdigest(),soak_report_sha256=hashlib.sha256((P/'evidence/soak.json').read_bytes()).hexdigest())
    except Exception as e:r.update(passed=False,status='failed',error=type(e).__name__+':'+str(e));raise
    finally:
        restored=command(['docker','context','use',context]);r['docker_context_restored']=restored.returncode==0 and checked(['docker','context','show']).stdout.strip()==context;r['passed']=r['passed'] and r['docker_context_restored'];save()
    print(json.dumps({'passed':r['passed'],'capacity_cases':len(r['capacity_phases']),'soak_seconds':r['soak_result']['observed_seconds']}));return 0 if r['passed'] else 1
if __name__=='__main__':sys.exit(main())
