"""Fixed local privileged writer. One bounded request/executor at a time."""
import fcntl,json,os,socket,stat,struct,subprocess,sys
from pathlib import Path

def serve(config_path):
    if os.geteuid()!=0:raise PermissionError('root writer required')
    config_path=Path(config_path);st=config_path.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_mode & 0o022:raise PermissionError('untrusted configuration')
    config=json.loads(config_path.read_text());lease_path=Path(config['lease'])
    fd=os.open(lease_path,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    try:
        st=os.fstat(fd)
        if st.st_uid!=0 or st.st_mode & 0o077:raise PermissionError('lease_permissions')
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        # Socket replacement is allowed only after acquiring the lifetime lease.
        endpoint=Path(config['socket'])
        if endpoint.exists():endpoint.unlink()
        with socket.socket(socket.AF_UNIX) as server:
            server.bind(str(endpoint));os.chown(endpoint,config['controller_uid'],-1);os.chmod(endpoint,0o600)
            server.listen(4)
            while True:
                conn,_=server.accept()
                with conn:
                    conn.settimeout(2)
                    _,uid,_=struct.unpack('3i',conn.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
                    if uid not in {0,config['controller_uid']}:
                        conn.sendall(b'{"ok":false,"error":"peer_denied"}\n');continue
                    try:
                        data=b''
                        while not data.endswith(b'\n'):
                            chunk=conn.recv(4096)
                            if not chunk:raise ValueError('incomplete')
                            data+=chunk
                            if len(data)>49152:raise ValueError('budget')
                        request=json.loads(data)
                        child=subprocess.Popen([sys.executable,'-m','certweft.executor',str(fd),str(config_path)],
                            pass_fds=(fd,),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                        try:out,err=child.communicate(json.dumps({'body':request,'peer_uid':uid}).encode(),timeout=20)
                        except subprocess.TimeoutExpired:
                            child.kill();child.communicate();raise TimeoutError('executor_timeout')
                        if child.returncode!=0 or len(out)>16384:raise RuntimeError('executor_failure')
                        reply=json.loads(out)
                    except Exception as e:reply={'ok':False,'error':type(e).__name__}
                    try:conn.sendall(json.dumps(reply).encode()+b'\n')
                    except OSError:pass
    finally:os.close(fd)

if __name__=='__main__':serve(sys.argv[1])
