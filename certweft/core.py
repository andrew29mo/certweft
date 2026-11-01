"""Single-writer exploratory backend. No implicit CA reload or shell execution."""
import contextlib
import fcntl
import hashlib
import json
import os
import re
from pathlib import Path
import socket
import sqlite3
import ssl
import subprocess
import time
import uuid
from . import deadlines

class Rejected(Exception):
    pass

def run(args, timeout=8):
    try:result=subprocess.run(list(map(str,args)), check=True, timeout=deadlines.timeout(timeout),capture_output=True).stdout
    except subprocess.TimeoutExpired:
        deadlines.check();raise
    deadlines.check();return result

def fingerprint(cert):
    return hashlib.sha256(run(['openssl','x509','-in',cert,'-outform','DER'])).hexdigest()

def validate(cert, key, root, host, margin=30):
    run(['openssl','verify','-CAfile',root,'-no-CApath','-no-CAstore',
         '-purpose','sslserver','-untrusted',cert,'-verify_hostname',host,cert])
    run(['openssl','x509','-in',cert,'-checkend',str(margin),'-noout'])
    public=run(['openssl','x509','-in',cert,'-pubkey','-noout'])
    if public != run(['openssl','pkey','-in',key,'-pubout']):
        raise Rejected('key_mismatch')
    text=run(['openssl','x509','-in',cert,'-text','-noout']).decode()
    if 'CA:TRUE' in text or 'TLS Web Server Authentication' not in text:
        raise Rejected('leaf_purpose')
    # Exploration supports only one explicit DNS SAN and P-256 keys.
    san=run(['openssl','x509','-in',cert,'-ext','subjectAltName','-noout']).decode()
    if san.strip().splitlines()[-1].strip() != 'DNS:'+host:
        raise Rejected('san_policy')
    algorithms=re.findall(r'Signature Algorithm: ([^\r\n]+)',text)
    eku=run(['openssl','x509','-in',cert,'-ext','extendedKeyUsage','-noout']).decode()
    if eku.strip().splitlines()[-1].strip()!='TLS Web Server Authentication':raise Rejected('eku_policy')
    if not re.search(r'^\s*ASN1 OID: prime256v1\s*$',text,re.M) or not algorithms or any(a.strip()!='ecdsa-with-SHA256' for a in algorithms):
        raise Rejected('algorithm_policy')
    return fingerprint(cert)

def probe(ip, port, host, root, expected, timeout=2):
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(cafile=str(root))
    ctx.minimum_version=ssl.TLSVersion.TLSv1_2
    with socket.create_connection((ip,port),deadlines.timeout(timeout)) as raw:
        raw.settimeout(deadlines.timeout(timeout))
        with ctx.wrap_socket(raw,server_hostname=host) as tls:
            if tls.session_reused or hashlib.sha256(tls.getpeercert(True)).hexdigest()!=expected:
                raise Rejected('wire_certificate')
            deadlines.check();tls.settimeout(deadlines.timeout(timeout))
            tls.sendall(('GET /health HTTP/1.1\r\nHost: '+host+'\r\nConnection: close\r\n\r\n').encode())
            data=b''; end=time.monotonic()+timeout
            while b'\r\n\r\n' not in data:
                tls.settimeout(deadlines.timeout(max(.001,end-time.monotonic())))
                chunk=tls.recv(1024)
                if not chunk:break
                data+=chunk
                if len(data)>4096 or time.monotonic()>end:raise Rejected('http_budget')
            if b'\r\n\r\n' not in data:raise Rejected('http_health')
            lines=data.split(b'\r\n\r\n',1)[0].split(b'\r\n')
            if not re.fullmatch(rb'HTTP/1\.1 200 [^\r\n]*',lines[0]):raise Rejected('http_health')
            if any(not re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+:[^\r\n]*",h) for h in lines[1:]):raise Rejected('http_headers')
    deadlines.check();return expected

class Writer:
    def __init__(self, root, nginx, conf, ca, key, host, ip, port):
        self.root=Path(root);self.root.mkdir(mode=0o700,parents=True,exist_ok=True)
        self.nginx=nginx;self.conf=str(conf);self.ca=Path(ca);self.key=Path(key)
        self.host=host;self.ip=ip;self.port=port
    @contextlib.contextmanager
    def locked(self):
        with open(self.root/'writer.lock','a+b') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            with contextlib.closing(sqlite3.connect(self.root/'journal.db',timeout=.2)) as db, db:
                db.execute('PRAGMA synchronous=FULL')
                db.execute('CREATE TABLE IF NOT EXISTS state (id INTEGER PRIMARY KEY CHECK(id=1), data TEXT NOT NULL)')
                yield db,lock
    def read(self,db):
        row=db.execute('SELECT data FROM state WHERE id=1').fetchone()
        if not row:raise Rejected('uninitialized')
        s=json.loads(row[0])
        if type(s) is not dict or s.get('schema')!=1 or s['state'] not in {'READY','APPLYING','DEGRADED'}:raise Rejected('journal_schema')
        for name in [s['committed'],s.get('candidate')]:
            if name and (len(name)!=32 or any(c not in '0123456789abcdef' for c in name)):raise Rejected('generation')
        active=self.root/'active.conf'
        known={'v-'+n+'/tls.conf' for n in [s['committed'],s.get('candidate')] if n}
        if not active.is_symlink() or os.readlink(active) not in known:raise Rejected('unknown_pointer')
        if self.digest(s['committed'])!=s['committed_digest']:raise Rejected('committed_drift')
        return s
    def digest(self,name):
        d=self.root/('v-'+name)
        return hashlib.sha256(b''.join((d/f).read_bytes() for f in ['cert.pem','key.pem','tls.conf'])).hexdigest()
    def save(self,db,s):
        try:
            db.execute('INSERT OR REPLACE INTO state VALUES(1,?)',(json.dumps(s),));db.commit()
        except Exception:
            db.rollback()
            raise
    def commit_state(self,db,state):
        self.save(db,state)
    def stage(self,cert):
        data=Path(cert).read_bytes()
        if len(data)>32768:raise Rejected('certificate_budget')
        if len(list(self.root.glob('v-*')))>=16:raise Rejected('version_capacity')
        name=uuid.uuid4().hex;d=self.root/('v-'+name);d.mkdir(mode=0o700)
        for dest,content in [('cert.pem',data),('key.pem',self.key.read_bytes())]:
            with open(d/dest,'xb') as f:
                os.chmod(d/dest,0o600);f.write(content);f.flush();os.fsync(f.fileno())
        (d/'tls.conf').write_text(f'ssl_certificate {d}/cert.pem;\nssl_certificate_key {d}/key.pem;\n')
        with open(d/'tls.conf','rb') as f:os.fsync(f.fileno())
        self.sync(d);self.sync(self.root)
        validate(d/'cert.pem',d/'key.pem',self.ca,self.host)
        return name
    @staticmethod
    def sync(path):
        fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(fd)
        finally:os.close(fd)
    def select(self,name):
        deadlines.check()
        tmp=self.root/'next'
        if tmp.is_symlink():tmp.unlink()
        tmp.symlink_to('v-'+name+'/tls.conf');deadlines.check();os.replace(tmp,self.root/'active.conf');self.sync(self.root)
    def check(self,name):
        d=self.root/('v-'+name)
        return validate(d/'cert.pem',d/'key.pem',self.ca,self.host)
    def reload(self):
        run([self.nginx,'-t','-c',self.conf]);run([self.nginx,'-s','reload','-c',self.conf])
    def confirm(self,name,end):
        expected=self.check(name);count=0
        while time.monotonic()<end:
            try:probe(self.ip,self.port,self.host,self.ca,expected);count+=1
            except (OSError,Rejected):count=0
            if count==3 and time.monotonic()<end:return expected
            time.sleep(deadlines.timeout(.1))
        raise Rejected('confirmation_timeout')
    def initialize(self,cert):
        with self.locked() as (db,lock):
            if db.execute('SELECT 1 FROM state').fetchone():raise Rejected('already_initialized')
            name=self.stage(cert);self.select(name)
            self.save(db,dict(schema=1,state='READY',epoch=uuid.uuid4().hex,revision=0,committed=name,committed_digest=self.digest(name),candidate=None))
            from .gate import Gate
            Gate(self.root).provision()
    def activate(self,cert,epoch,revision,checkpoint=lambda x:None):
        with self.locked() as (db,lock):
            s=self.read(db)
            if (s['epoch'],s['revision'],s['state'])!=(epoch,revision,'READY'):raise Rejected('stale_or_not_ready')
            self.confirm(s['committed'],time.monotonic()+3)
            name=self.stage(cert);end=time.monotonic()+5
            s.update(state='APPLYING',candidate=name,revision=s['revision']+1)
            self.save(db,s);checkpoint('intent')
            try:
                self.select(name);checkpoint('selected');self.reload();checkpoint('reload')
                self.confirm(name,end);checkpoint('confirmed')
                if time.monotonic()>=end:raise Rejected('expired')
                self.check(name)
                if time.monotonic()>=end:raise Rejected('expired')
                s.update(committed=name,committed_digest=self.digest(name),candidate=None,state='READY');self.commit_state(db,s)
            except Exception:
                db.rollback()
                # Recover uses durable state, never an in-memory partially committed object.
                self.recover_locked(db);raise
            return s
    def recover_locked(self,db):
        s=self.read(db)
        try:
            self.check(s['committed']);self.select(s['committed']);self.reload()
            self.confirm(s['committed'],time.monotonic()+5)
            s.update(state='READY',candidate=None,epoch=uuid.uuid4().hex,revision=s['revision']+1)
            self.save(db,s)
        except Exception:
            s['state']='DEGRADED'
            try:self.save(db,s)
            except sqlite3.Error:pass
            raise
        return s
    def recover(self):
        with self.locked() as (db,lock):return self.recover_locked(db)
    def status(self):
        # Observation must never create missing schema in a quarantined journal.
        with open(self.root/'writer.lock','a+b') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            with contextlib.closing(sqlite3.connect((self.root/'journal.db').resolve().as_uri()+'?mode=ro',uri=True,timeout=.2)) as db:
                return self.read(db)
