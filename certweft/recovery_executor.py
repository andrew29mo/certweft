"""Root storage verifier with inherited lifetime lease; no Nginx mutation API."""
import json,os,signal,sys
from pathlib import Path
from .recovery import verify
from .core import Rejected

def main():
    if os.geteuid()!=0:raise PermissionError('root verifier required')
    lease=int(sys.argv[1]);message=json.load(sys.stdin);config=message['config'];body=message['body']
    actual=os.fstat(lease);expected=os.stat(config['lease'])
    if (actual.st_dev,actual.st_ino)!=(expected.st_dev,expected.st_ino):raise Rejected('lease_identity')
    if message['peer_uid']!=0 or set(body)!={'op','request_id'} or body['op']!='run-verification':raise Rejected('admin_required')
    def checkpoint(point):
        if config.get('verification_pause_at')==point:
            marker=Path(config['verification_marker'])
            if config.get('verification_pause_once') and marker.exists():return
            pending=marker.with_suffix('.pending')
            pending.write_text(json.dumps({'pid':os.getpid(),'point':point}));os.replace(pending,marker);os.kill(os.getpid(),signal.SIGSTOP)
    try:result={'ok':True,'result':verify(config,body['request_id'],checkpoint)}
    except Exception as error:
        result={'ok':False,'error':type(error).__name__,'sqlite_error':getattr(error,'sqlite_errorname',None),'errno':getattr(error,'errno',None)}
    print(json.dumps(result))
if __name__=='__main__':main()
