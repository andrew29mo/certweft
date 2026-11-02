"""Bounded local client and explicit administrator installation/recovery commands."""
import argparse,json,os,pathlib,re,socket,sys,time
from .core import Rejected

DEFAULT_SOCKET='/run/certweft/control.sock'
def call(endpoint,body):
    with socket.socket(socket.AF_UNIX) as s:
        s.settimeout(3);s.connect(endpoint);s.sendall(json.dumps(body).encode()+b'\n');data=b''
        while not data.endswith(b'\n'):
            part=s.recv(4096)
            if not part:raise Rejected('service_closed')
            data+=part
            if len(data)>65536:raise Rejected('reply_budget')
        result=json.loads(data)
    if type(result) is not dict or result.get('ok') is not True:raise Rejected(result.get('reason',result.get('error','service_error')) if type(result) is dict else 'reply_schema')
    return result

def wait(endpoint,identity,root=False,seconds=25):
    until=time.monotonic()+seconds
    while time.monotonic()<until:
        try:r=call(endpoint,{'op':'recovery-request-status' if root else 'request-status','request_id':identity})['result']
        except Rejected as e:
            if str(e)!='decision_busy':raise
            time.sleep(.03);continue
        if r['state'] not in {'ACCEPTED','RUNNING','CANCEL_REQUESTED','CERTIFICATE_VERIFIED'}:
            if not root or not call(endpoint,{'op':'recovery-status'})['executor_busy']:return r
        time.sleep(.03)
    raise Rejected('client_wait_timeout_outcome_unknown')

def recover(endpoint,prefix,seconds):
    if os.geteuid()!=0:raise Rejected('admin_required')
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,40}',prefix):raise Rejected('request_prefix')
    gate=call(endpoint,{'op':'recovery-status'})['gate']
    if gate['state']=='RECOVERY_REQUIRED':gate=call(endpoint,{'op':'prepare-recovery','gate_epoch':gate['epoch'],'gate_revision':gate['revision']})['gate']
    if gate['state'] not in {'VERIFY_REQUIRED','VERIFIED_CLOSED'}:raise Rejected('recovery_closed_gate_required')
    results=[]
    for kind,suffix,expected in [('recover-certificate','cert','VERIFIED_CLOSED'),('reconcile-closed','journal','JOURNAL_VERIFIED_CLOSED'),('prepare-opening','intent','OPENING_VERIFIED_CLOSED'),('prepare-release','release','RELEASE_VERIFIED_CLOSED'),('open-updates','open','OPENED')]:
        identity=prefix+'-'+suffix;old=None
        try:old=call(endpoint,{'op':'recovery-request-status','request_id':identity})['result']
        except Rejected as e:
            if str(e)!='unknown_recovery_request':raise
        if old is not None:
            if old['kind']!=kind:raise Rejected('request_conflict')
        else:
            current=call(endpoint,{'op':'recovery-status'})['gate']
            body={'op':kind,'request_id':identity,'timeout_seconds':seconds,'gate_epoch':current['epoch'],'gate_revision':current['revision']}
            if kind=='reconcile-closed':body['certificate_request_id']=results[-1]['request_id']
            elif kind=='prepare-opening':
                prior=results[-1]
                # Reconciliation creates a new core epoch/revision. Read the
                # resulting public core rather than the pre-reconciliation target.
                core=call(endpoint,{'op':'status'})['result']
                body.update(preparation_request_id=prior['request_id'],receipt_digest=prior['result']['receipt_digest'],core_epoch=core['epoch'],core_revision=core['revision'])
            elif kind=='prepare-release':body.update(opening_request_id=results[-1]['request_id'],opening_marker_digest=results[-1]['result']['marker_digest'])
            elif kind=='open-updates':body.update(release_request_id=results[-1]['request_id'],release_receipt_digest=results[-1]['result']['receipt_digest'])
            call(endpoint,body)
        result=wait(endpoint,identity,True)
        if result['kind']!=kind or result['state']!=expected:raise Rejected('recovery_step_'+result['state'])
        results.append(result)
    current=call(endpoint,{'op':'recovery-status'})
    if not current['gate_allows_updates']:raise Rejected('historical_completion_not_current_permission')
    return {'ok':True,'updates_enabled':True,'requests':[r['request_id'] for r in results],'gate':current['gate']}

def parser():
    p=argparse.ArgumentParser(prog='certweft');p.add_argument('--socket',default=DEFAULT_SOCKET)
    sub=p.add_subparsers(dest='command',required=True)
    sub.add_parser('status');sub.add_parser('gate')
    submit=sub.add_parser('submit');submit.add_argument('--certificate',required=True);submit.add_argument('--request-id',required=True);submit.add_argument('--epoch',required=True);submit.add_argument('--revision',required=True,type=int);submit.add_argument('--timeout',type=int,choices=range(1,11),default=10);submit.add_argument('--wait',action='store_true')
    for name in ['request-status','cancel']:
        s=sub.add_parser(name);s.add_argument('--request-id',required=True)
    hist=sub.add_parser('recovery-request-status');hist.add_argument('--request-id',required=True)
    rec=sub.add_parser('recover');rec.add_argument('--prefix',required=True);rec.add_argument('--timeout',type=int,choices=range(1,11),default=10)
    ins=sub.add_parser('install')
    for name in ['certificate','key','ca-root','credential','issuer-url','step']:ins.add_argument('--'+name,required=True)
    ins.add_argument('--port',type=int,default=19443)
    issue=sub.add_parser('issue');issue.add_argument('--config',default='/etc/certweft/issuer.json');issue.add_argument('--request-id',required=True)
    return p

def main():
    args=parser().parse_args();os.umask(0o077)
    try:
        if args.command=='install':
            from .deployment import install
            result=install(args.certificate,args.key,args.ca_root,args.credential,args.issuer_url,args.step,args.port)
        elif args.command=='issue':
            from .deployment import issue
            result=issue(args.config,args.request_id)
        elif args.command=='recover':result=recover(args.socket,args.prefix,args.timeout)
        else:
            op={'gate':'recovery-status'}.get(args.command,args.command);body={'op':op}
            if hasattr(args,'request_id'):body['request_id']=args.request_id
            if op=='submit':
                with open(args.certificate,'rb') as f:data=f.read(32769)
                if len(data)>32768:raise Rejected('certificate_budget')
                body.update(certificate=data.decode(),epoch=args.epoch,revision=args.revision,timeout_seconds=args.timeout)
            result=call(args.socket,body)
            if op=='submit' and args.wait:result={'ok':True,'result':wait(args.socket,args.request_id)}
            if op=='submit' and args.wait and result['result']['state']!='COMMITTED':raise Rejected('activation_'+result['result']['state'])
        print(json.dumps(result));return 0
    except Exception as error:
        print(json.dumps({'ok':False,'error':type(error).__name__,'reason':str(error) if isinstance(error,Rejected) else None}),file=sys.stderr);return 1

if __name__=='__main__':sys.exit(main())
