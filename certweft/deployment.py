"""Single-instance installation and fresh Nginx identity binding. Root only."""
import importlib.resources,json,os,pathlib,pwd,grp,re,select,shutil,stat,subprocess
from .core import Writer,Rejected,validate
from .operations import Operations
from .recovery import RecoveryStore

ETC=pathlib.Path('/etc/certweft');STATE=pathlib.Path('/var/lib/certweft')

def master_identity(path,nginx,unit=None):
    from .service import secure_parents
    secure_parents(path)
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(fd) as f:
        s=os.fstat(f.fileno());text=f.read(33)
        if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_mode & 0o022 or not re.fullmatch(r'[1-9][0-9]{0,9}\n?',text):raise Rejected('master_pid_file')
    pid=int(text);handle=os.pidfd_open(pid)
    try:
        poll=select.poll();poll.register(handle,select.POLLIN)
        if poll.poll(0):raise Rejected('master_exited')
        raw=pathlib.Path('/proc',str(pid),'stat').read_text();start=raw[raw.rfind(')')+2:].split()[19]
        if unit is None:
            if os.path.realpath('/proc/'+str(pid)+'/exe')!=os.path.realpath(nginx) or poll.poll(0):raise Rejected('master_binary')
            return {'pid':pid,'start':start}
        current=unit_identity(unit,nginx)
        if current['pid']!=pid or poll.poll(0):raise Rejected('master_unit_pid')
        return {**current,'start':start}
    finally:os.close(handle)

def unit_identity(unit,nginx):
    # Read-only manager metadata replaces cross-capability /proc/exe inspection.
    # Fixed unit bytes, loaded command and absence of drop-ins are all required.
    if unit!='certweft-nginx.service' or nginx!='/usr/sbin/nginx':raise Rejected('fixed_master_unit')
    from .service import secure_parents
    path=pathlib.Path('/etc/systemd/system')/unit;secure_parents(path);s=path.lstat()
    if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_mode & 0o022 or path.read_bytes()!=(importlib.resources.files('certweft')/'assets'/unit).read_bytes():raise Rejected('master_unit_file')
    from .core import run
    raw=run(['/usr/bin/systemctl','show',unit,'-p','MainPID','-p','InvocationID','-p','ActiveState','-p','FragmentPath','-p','DropInPaths','-p','ExecStart'],2).decode()
    p=dict(line.split('=',1) for line in raw.splitlines() if '=' in line)
    if p['ActiveState']!='active' or p['FragmentPath']!=str(path) or p['DropInPaths'] or not re.fullmatch('[0-9a-f]{32}',p['InvocationID']):raise Rejected('master_unit_state')
    command=p['ExecStart'].split(' ; ')
    if len(command)<2 or command[0]!='{ path=/usr/sbin/nginx' or command[1]!='argv[]=/usr/sbin/nginx -c /etc/certweft/nginx.conf':raise Rejected('master_unit_command')
    if not re.fullmatch('[1-9][0-9]{0,9}',p['MainPID']):raise Rejected('master_unit_pid')
    return {'pid':int(p['MainPID']),'unit':unit,'invocation':p['InvocationID'],'binding':'systemd'}

def verify_unit_master(master,nginx):
    current=unit_identity(master['unit'],nginx)
    if any(current[k]!=master[k] for k in ['pid','unit','invocation','binding']):raise Rejected('master_unit_changed')

def account(name):
    try:pwd.getpwnam(name)
    except KeyError:
        subprocess.run(['useradd','--system','--no-create-home','--shell','/usr/sbin/nologin',name],check=True,capture_output=True);p=pwd.getpwnam(name)
    else:raise Rejected('account_conflict')
    if p.pw_uid==0 or p.pw_shell!='/usr/sbin/nologin':raise Rejected('account_conflict')
    return p

def write(path,data,mode=0o600,gid=None):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
    os.fchmod(fd,mode)
    with os.fdopen(fd,'wb') as f:f.write(data);f.flush();os.fsync(f.fileno())
    if gid is not None:os.chown(path,0,gid)
    Writer.sync(path.parent)

def install(certificate,key,ca_root,credential,issuer_url,step,port):
    if os.geteuid()!=0:raise Rejected('admin_required')
    if not 1024<=port<=65535 or not re.fullmatch(r'https://localhost:[1-9][0-9]{0,4}',issuer_url):raise Rejected('fixed_target_policy')
    if any(p.exists() for p in [ETC,STATE,pathlib.Path('/var/lib/certweft-candidates'),pathlib.Path('/var/log/certweft-nginx')]) or any((pathlib.Path('/etc/systemd/system')/n).exists() for n in ['certweft.service','certweft-nginx.service','certweft-issue@.service']):raise Rejected('installation_exists')
    from .service import secure_parents
    for name in ['certweft-operator','certweft-signer']:
        for lookup in [pwd.getpwnam,grp.getgrnam]:
            try:lookup(name)
            except KeyError:pass
            else:raise Rejected('account_conflict')
    for path,budget in [(certificate,32768),(key,16384),(ca_root,131072),(credential,4096)]:
        p=pathlib.Path(path);secure_parents(p);s=p.lstat()
        if not 0<s.st_size<=budget:raise Rejected('bootstrap_budget')
        if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_mode & 0o022:raise Rejected('bootstrap_permissions')
    step=pathlib.Path(step);secure_parents(step);s=step.lstat()
    if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_mode & 0o022:raise Rejected('step_permissions')
    validate(certificate,key,ca_root,'localhost')
    operator=account('certweft-operator');signer=account('certweft-signer')
    ETC.mkdir(mode=0o755);os.chmod(ETC,0o755);STATE.mkdir(mode=0o700)
    write(ETC/'ca.pem',pathlib.Path(ca_root).read_bytes(),0o644)
    write(ETC/'service.key',pathlib.Path(key).read_bytes(),0o440,signer.pw_gid)
    write(ETC/'provisioner-password',pathlib.Path(credential).read_bytes())
    candidates=pathlib.Path('/var/lib/certweft-candidates')
    if candidates.exists():raise Rejected('candidate_directory_exists')
    candidates.mkdir(mode=0o750);os.chown(candidates,signer.pw_uid,operator.pw_gid);os.chmod(candidates,0o2750)
    logs=pathlib.Path('/var/log/certweft-nginx')
    if logs.exists():raise Rejected('log_directory_exists')
    logs.mkdir(mode=0o755);os.chmod(logs,0o755)
    writer={'root':str(STATE),'nginx':'/usr/sbin/nginx','conf':str(ETC/'nginx.conf'),'ca':str(ETC/'ca.pem'),'key':str(ETC/'service.key'),'host':'localhost','ip':'127.0.0.1','port':port}
    w=Writer(**writer);w.initialize(certificate);Operations(STATE).initialize();RecoveryStore(STATE).initialize()
    nginx=f'''pid /run/certweft-nginx/master.pid;
error_log /var/log/certweft-nginx/error.log;
events {{}}
http {{ access_log off;
client_body_temp_path /run/certweft-nginx/body;
proxy_temp_path /run/certweft-nginx/proxy;
fastcgi_temp_path /run/certweft-nginx/fastcgi;
uwsgi_temp_path /run/certweft-nginx/uwsgi;
scgi_temp_path /run/certweft-nginx/scgi;
server {{ listen 127.0.0.1:{port} ssl; server_name localhost;
include /var/lib/certweft/active.conf;
location = /health {{ return 200 "ok"; }} }} }}
'''
    write(ETC/'nginx.conf',nginx.encode(),0o644)
    cfg={'writer':writer,'controller_uid':operator.pw_uid,'socket':'/run/certweft/control.sock','lease':str(STATE/'lifetime.lock'),'master_pid_file':'/run/certweft-nginx/master.pid','master_unit':'certweft-nginx.service','isolated_executors':True}
    write(ETC/'writer.json',json.dumps(cfg).encode())
    issuer={'step':str(step),'ca_url':issuer_url,'root':str(ETC/'ca.pem'),'key':str(ETC/'service.key'),'output':str(candidates)}
    write(ETC/'issuer.json',json.dumps(issuer).encode(),0o644)
    assets=importlib.resources.files('certweft')/'assets'
    for name in ['certweft.service','certweft-nginx.service','certweft-issue@.service']:write(pathlib.Path('/etc/systemd/system')/name,(assets/name).read_bytes(),0o644)
    subprocess.run(['systemctl','daemon-reload'],check=True,capture_output=True)
    return {'installed':True,'started':False,'controller_uid':operator.pw_uid,'fixed_host':'localhost','port':port}

def issue(config,identity):
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,64}',identity):raise Rejected('request_id')
    from .service import secure_parents
    secure_parents(config);p=pathlib.Path(config);s=p.lstat()
    if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_mode & 0o022:raise Rejected('issuer_permissions')
    cfg=json.loads(p.read_text())
    if set(cfg)!={'step','ca_url','root','key','output'}:raise Rejected('issuer_schema')
    directory=pathlib.Path(cfg['output'])/identity
    directory.mkdir(mode=0o750) # Existing/partial output never silently replayed.
    os.chmod(directory,0o2750)
    from .ca import reissue_credential
    target=directory/'cert.pem';reissue_credential(cfg['step'],cfg['ca_url'],cfg['root'],cfg['key'],target)
    fp=validate(target,cfg['key'],cfg['root'],'localhost');os.chmod(target,0o640);Writer.sync(directory)
    return {'issued':True,'request_id':identity,'fingerprint':fp,'activated':False}
