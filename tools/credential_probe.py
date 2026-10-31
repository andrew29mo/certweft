"""VM-only observation wrapper; issuance calls the production credential adapter."""
import sys,os,pathlib,json,time
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
from certweft.ca import reissue_credential

def main():
    reissue_credential(*sys.argv[1:])
    target=pathlib.Path(sys.argv[-1]).parent
    cred=pathlib.Path(os.environ['CREDENTIALS_DIRECTORY'])/'provisioner-password'
    st=cred.stat()
    status=pathlib.Path('/proc/self/status').read_text()
    cap=next(x.split()[1] for x in status.splitlines() if x.startswith('CapEff:'))
    record={'uid':os.geteuid(),'gid':os.getegid(),'caps':cap,'credential_mode':oct(st.st_mode & 0o777),'credential_path':str(cred)}
    pending=target/'observed.pending'
    pending.write_text(json.dumps(record))
    os.replace(pending,target/'observed.json')
    end=time.monotonic()+8
    while not (target/'release').exists():
        if time.monotonic()>end:raise RuntimeError('observation_timeout')
        time.sleep(.02)
    print('issued_and_observed')
if __name__=='__main__':main()
