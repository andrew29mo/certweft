"""Preexisting execution uncertainty record. Root service owns all transitions.

Not a recovery backend: preparing recovery never enables updates or changes TLS.
"""
import hashlib,json,os,re,stat,uuid
from pathlib import Path
from .core import Rejected

class Gate:
    def __init__(self,root):
        self.root=Path(root);self.path=self.root/'execution.json';self.receipt=self.root/'execution-clean.json';self.checkpoint=lambda point,state:None
    def read(self):
        fd=os.open(self.path,os.O_RDONLY|os.O_NOFOLLOW)
        with os.fdopen(fd,'rb') as stream:
            st=os.fstat(stream.fileno())
            if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.geteuid() or st.st_mode & 0o077:raise Rejected('gate_permissions')
            data=stream.read(4097)
        if len(data)>4096:raise Rejected('gate_budget')
        try:s=json.loads(data)
        except (ValueError,UnicodeError):raise Rejected('gate_schema')
        if type(s) is not dict or set(s)!={'version','epoch','revision','state','reason'}:raise Rejected('gate_schema')
        if type(s['version']) is not int or s['version']!=1 or type(s['epoch']) is not str or not re.fullmatch('[0-9a-f]{32}',s['epoch']):raise Rejected('gate_schema')
        if type(s['revision']) is not int or not 0<=s['revision']<2**63-1:raise Rejected('gate_schema')
        if s['state'] not in {'STOPPED','RUNNING','RECOVERY_REQUIRED','VERIFY_REQUIRED'} or s['reason'] not in {'new_store','clean_stop','session_started','unclean_or_blocked','legacy_store','pending_on_clean_start','operator_prepared'}:raise Rejected('gate_schema')
        return s
    def certified(self,s):
        try:fd=os.open(self.receipt,os.O_RDONLY|os.O_NOFOLLOW)
        except FileNotFoundError:return False
        with os.fdopen(fd,'rb') as stream:
            st=os.fstat(stream.fileno())
            if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.geteuid() or st.st_mode & 0o077:raise Rejected('receipt_permissions')
            data=stream.read(4097)
        if len(data)>4096:raise Rejected('receipt_budget')
        try:receipt=json.loads(data)
        except (ValueError,UnicodeError):raise Rejected('receipt_schema')
        if type(receipt) is not dict or set(receipt)!={'version','epoch','revision','sha256'} or type(receipt['version']) is not int or type(receipt['revision']) is not int or type(receipt['epoch']) is not str or type(receipt['sha256']) is not str:return False
        expected={'version':1,'epoch':s['epoch'],'revision':s['revision'],'sha256':hashlib.sha256(json.dumps(s,sort_keys=True).encode()).hexdigest()}
        return type(receipt) is dict and receipt==expected
    def certify(self,s):
        # Only issued after the primary STOPPED record's directory fsync succeeds.
        receipt={'version':1,'epoch':s['epoch'],'revision':s['revision'],'sha256':hashlib.sha256(json.dumps(s,sort_keys=True).encode()).hexdigest()}
        self.publish(self.receipt,receipt)
        return s
    def publish(self,path,s,primary=False):
        pending=self.root/('execution-'+uuid.uuid4().hex+'.pending');fd=os.open(pending,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        try:
            with os.fdopen(fd,'wb') as stream:
                stream.write(json.dumps(s,sort_keys=True).encode());stream.flush();os.fsync(stream.fileno())
            os.replace(pending,path)
            directory=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY)
            try:
                if primary:self.checkpoint('directory-sync',s)
                os.fsync(directory)
            finally:os.close(directory)
        finally:pending.unlink(missing_ok=True)
        return s
    def write(self,s):
        if type(s.get('revision')) is not int or not 0<=s['revision']<2**63-1:raise Rejected('gate_revision_exhausted')
        return self.publish(self.path,s,primary=True)
    def provision(self):
        # Called only by Writer.initialize after creating a new committed baseline.
        if self.path.exists() or self.path.is_symlink():raise Rejected('gate_already_exists')
        return self.certify(self.write({'version':1,'epoch':uuid.uuid4().hex,'revision':0,'state':'STOPPED','reason':'new_store'}))
    def start(self):
        try:old=self.read()
        except FileNotFoundError:
            old={'version':1,'epoch':uuid.uuid4().hex,'revision':0,'state':'RECOVERY_REQUIRED','reason':'legacy_store'}
            state='RECOVERY_REQUIRED';reason='legacy_store'
        else:
            state='RUNNING' if old['state']=='STOPPED' and self.certified(old) else 'RECOVERY_REQUIRED'
            reason='session_started' if state=='RUNNING' else 'unclean_or_blocked'
        return self.write({**old,'epoch':uuid.uuid4().hex,'revision':old['revision']+1,'state':state,'reason':reason})
    @staticmethod
    def token(s):return {'gate_epoch':s['epoch'],'gate_revision':s['revision']}
    def require(self,authority):
        s=self.read()
        if self.token(s)!=authority:raise Rejected('stale_gate_authority')
        if s['state']!='RUNNING':raise Rejected('recovery_required')
        return s
    def stop(self,authority):
        s=self.require(authority)
        return self.certify(self.write({**s,'revision':s['revision']+1,'state':'STOPPED','reason':'clean_stop'}))
    def block(self,authority):
        s=self.require(authority)
        return self.write({**s,'revision':s['revision']+1,'state':'RECOVERY_REQUIRED','reason':'pending_on_clean_start'})
    def prepare(self,authority):
        s=self.read()
        if self.token(s)!=authority:raise Rejected('stale_gate_authority')
        if s['state']!='RECOVERY_REQUIRED':raise Rejected('not_recovery_required')
        return self.write({**s,'revision':s['revision']+1,'state':'VERIFY_REQUIRED','reason':'operator_prepared'})
