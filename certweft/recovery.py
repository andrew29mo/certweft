"""Bounded durable root storage-verification operations. Never restores or unlocks."""
import contextlib,hashlib,json,os,re,sqlite3,stat,uuid
from pathlib import Path
from . import deadlines
from .core import Writer,Rejected
from .gate import Gate
from .operations import decision
LIVE=('ACCEPTED','RUNNING')

class RecoveryStore:
    def __init__(self,root):self.root=Path(root);self.path=self.root/'recovery.db'
    @contextlib.contextmanager
    def transaction(self,before_commit=lambda:None):
        with decision(self.root/'journal.db'):
            db=sqlite3.connect(self.path,timeout=.5)
            try:
                db.execute('PRAGMA synchronous=FULL')
                if db.execute('PRAGMA max_page_count=128').fetchone()[0]!=128:raise Rejected('recovery_quota')
                db.execute('BEGIN IMMEDIATE')
                yield db;before_commit();db.commit()
            except Exception:db.rollback();raise
            finally:db.close()
    def initialize(self):
        existed=self.path.exists()
        if existed:
            st=self.path.lstat()
            if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.geteuid() or st.st_mode & 0o077:raise Rejected('recovery_permissions')
        else:
            fd=os.open(self.path,os.O_CREAT|os.O_EXCL|os.O_RDWR|os.O_NOFOLLOW,0o600);os.close(fd)
        with self.transaction() as db:
            if existed:
                if db.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").fetchall()!=[('recovery_meta',),('recovery_requests',)]:raise Rejected('recovery_schema')
                if [r[1] for r in db.execute('PRAGMA table_info(recovery_requests)')]!=['id','digest','state','timing','target','probe','result']:raise Rejected('recovery_schema')
            db.execute('CREATE TABLE IF NOT EXISTS recovery_meta(version INTEGER NOT NULL)')
            if not existed:db.execute('INSERT INTO recovery_meta VALUES(1)')
            if db.execute('SELECT version FROM recovery_meta').fetchall()!=[(1,)]:raise Rejected('recovery_schema')
            db.execute('CREATE TABLE IF NOT EXISTS recovery_requests(id TEXT PRIMARY KEY,digest TEXT NOT NULL,state TEXT NOT NULL,timing TEXT NOT NULL,target TEXT NOT NULL,probe TEXT NOT NULL,result TEXT)')
            db.execute("CREATE UNIQUE INDEX IF NOT EXISTS one_recovery ON recovery_requests((1)) WHERE state IN ('ACCEPTED','RUNNING')")
            identities=list(db.execute('SELECT id FROM recovery_requests LIMIT 17'))
            if len(identities)>16:raise Rejected('recovery_schema')
            for (identity,) in identities:self.row(db,identity)
        Writer.sync(self.root)
    @staticmethod
    def identity(body):
        if set(body)!={'op','request_id','gate_epoch','gate_revision','timeout_seconds'} or body['op']!='verify-storage':raise Rejected('request_shape')
        if type(body['request_id']) is not str or not re.fullmatch('[A-Za-z0-9_-]{1,64}',body['request_id']):raise Rejected('request_id')
        if type(body['gate_epoch']) is not str or type(body['gate_revision']) is not int:raise Rejected('authority_shape')
        if type(body['timeout_seconds']) is not int or not 1<=body['timeout_seconds']<=10:raise Rejected('timeout_policy')
        return hashlib.sha256(json.dumps({k:v for k,v in body.items() if k!='request_id'},sort_keys=True).encode()).hexdigest()
    @staticmethod
    def row(db,identity):
        r=db.execute('SELECT digest,state,timing,target,probe,result FROM recovery_requests WHERE id=?',(identity,)).fetchone()
        if not r:raise Rejected('unknown_recovery_request')
        if type(identity) is not str or not re.fullmatch('[A-Za-z0-9_-]{1,64}',identity):raise Rejected('recovery_schema')
        if type(r[0]) is not str or not re.fullmatch('[0-9a-f]{64}',r[0]) or r[1] not in {'ACCEPTED','RUNNING','STORAGE_VERIFIED','FAILED','EXPIRED','INTERRUPTED'} or type(r[4]) is not str or not re.fullmatch('[0-9a-f]{32}',r[4]):raise Rejected('recovery_schema')
        if any(type(value) is not str or len(value)>16384 for value in [r[2],r[3]]) or r[5] is not None and (type(r[5]) is not str or len(r[5])>16384):raise Rejected('recovery_schema')
        row=dict(request_id=identity,digest=r[0],state=r[1],timing=json.loads(r[2]),target=json.loads(r[3]),probe=r[4],result=json.loads(r[5]) if r[5] else None)
        if type(row['timing']) is not dict or set(row['timing'])!={'budget','authority'} or type(row['target']) is not dict:raise Rejected('recovery_schema')
        budget=row['timing']['budget'];authority=row['timing']['authority']
        fields={'version','boot_id','accepted_boot_ns','expires_boot_ns','accepted_wall_ns','seconds'}
        if type(budget) is not dict or set(budget)!=fields:raise Rejected('recovery_schema')
        if any(type(budget[k]) is not int for k in fields-{'boot_id'}):raise Rejected('recovery_schema')
        if budget['version']!=1 or not 1<=budget['seconds']<=10:raise Rejected('recovery_schema')
        if type(budget['boot_id']) is not str or not re.fullmatch('[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}',budget['boot_id']):raise Rejected('recovery_schema')
        if any(not 0<=budget[k]<2**63 for k in ['accepted_boot_ns','expires_boot_ns','accepted_wall_ns']):raise Rejected('recovery_schema')
        if budget['expires_boot_ns']-budget['accepted_boot_ns']!=budget['seconds']*1_000_000_000:raise Rejected('recovery_schema')
        if type(authority) is not dict or set(authority)!={'gate_epoch','gate_revision'}:raise Rejected('recovery_schema')
        if type(authority['gate_epoch']) is not str or not re.fullmatch('[0-9a-f]{32}',authority['gate_epoch']) or type(authority['gate_revision']) is not int or not 0<=authority['gate_revision']<2**63-1:raise Rejected('recovery_schema')
        canonical={'op':'verify-storage','request_id':identity,**authority,'timeout_seconds':budget['seconds']}
        if RecoveryStore.identity(canonical)!=row['digest']:raise Rejected('recovery_schema')
        return row
    def get(self,identity):
        with self.transaction() as db:return self.row(db,identity)
    def admit(self,body,writer):
        digest=self.identity(body)
        with self.transaction() as db:
            if db.execute('SELECT 1 FROM recovery_requests WHERE id=?',(body['request_id'],)).fetchone():
                old=self.row(db,body['request_id'])
                if old['digest']!=digest:raise Rejected('request_conflict')
                return old,False
            gate=Gate(self.root).read()
            if Gate.token(gate)!={k:body[k] for k in ['gate_epoch','gate_revision']}:raise Rejected('stale_gate_authority')
            if gate['state']!='VERIFY_REQUIRED':raise Rejected('prepare_required')
            if db.execute('SELECT count(*) FROM recovery_requests').fetchone()[0]>=16:raise Rejected('recovery_history_full')
            if db.execute("SELECT 1 FROM recovery_requests WHERE state IN ('ACCEPTED','RUNNING')").fetchone():raise Rejected('busy')
            with contextlib.closing(open_main(writer)) as main:target=writer.read(main)
            timing={'budget':deadlines.create(body['timeout_seconds']),'authority':Gate.token(gate)}
            db.execute('INSERT INTO recovery_requests VALUES(?,?,?,?,?,?,NULL)',(body['request_id'],digest,'ACCEPTED',json.dumps(timing),json.dumps(target),uuid.uuid4().hex))
            return self.row(db,body['request_id']),True
    def begin(self,identity):
        with self.transaction() as db:
            row=self.row(db,identity)
            if row['state']!='ACCEPTED':raise Rejected('not_accepted')
            deadlines.remaining(row['timing']['budget']);require_authority(self.root,row)
            db.execute("UPDATE recovery_requests SET state='RUNNING' WHERE id=?",(identity,))
            return row
    def finish(self,identity,state,result):
        authorized=[None]
        def final_authorization():
            if authorized[0] is not None:
                getattr(self,'commit_checkpoint',lambda:None)()
                deadlines.remaining(authorized[0]['timing']['budget']);require_authority(self.root,authorized[0])
        with self.transaction(final_authorization) as db:
            row=self.row(db,identity)
            if row['state'] not in LIVE:return row
            if state=='STORAGE_VERIFIED':
                deadlines.remaining(row['timing']['budget']);require_authority(self.root,row);authorized[0]=row
            db.execute('UPDATE recovery_requests SET state=?,result=? WHERE id=?',(state,json.dumps(result),identity))
            return self.row(db,identity)
    def reconcile(self):
        with self.transaction() as db:
            pending=list(db.execute("SELECT id FROM recovery_requests WHERE state IN ('ACCEPTED','RUNNING')"))
            for (identity,) in pending:
                row=self.row(db,identity)
                try:deadlines.remaining(row['timing']['budget']);state='INTERRUPTED'
                except deadlines.Expired:state='EXPIRED'
                db.execute('UPDATE recovery_requests SET state=?,result=? WHERE id=?',(state,json.dumps({'replayed':False,'storage_verified':False,'updates_enabled':False,'restored':False}),identity))
            return bool(pending)

def require_authority(root,row):
    gate=Gate(root).read()
    if Gate.token(gate)!=row['timing']['authority']:raise Rejected('stale_gate_authority')
    if gate['state']!='VERIFY_REQUIRED':raise Rejected('prepare_required')

def open_main(writer,max_pages=None):
    path=writer.root/'journal.db';st=path.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.geteuid() or st.st_mode & 0o077:raise Rejected('journal_permissions')
    db=sqlite3.connect(path.resolve().as_uri()+'?mode=rw',uri=True,timeout=deadlines.timeout(.5))
    try:
        db.execute('PRAGMA synchronous=FULL')
        if max_pages is not None:
            if type(max_pages) is not int or not 1<=max_pages<=65536:raise Rejected('sqlite_page_policy')
            if db.execute('PRAGMA max_page_count='+str(max_pages)).fetchone()[0]!=max_pages:raise Rejected('sqlite_quota_below_size')
        def progress():
            try:deadlines.check();return 0
            except deadlines.Expired:return 1
        db.set_progress_handler(progress,1000)
        return db
    except Exception:db.close();raise

def validate_journal(db,writer,target):
    try:
        if db.execute('PRAGMA integrity_check(1)').fetchall()!=[('ok',)]:raise Rejected('journal_integrity')
        expected={'state':['id','data'],'health':['id','state','detail'],'requests':['id','digest','state','result','timing'],'storage_probe':['id','value']}
        for name,columns in expected.items():
            if db.execute('SELECT type FROM sqlite_master WHERE name=?',(name,)).fetchone()!=('table',):raise Rejected('journal_schema')
            if [r[1] for r in db.execute('PRAGMA table_info('+name+')')]!=columns:raise Rejected('journal_schema')
        if db.execute('SELECT id FROM state').fetchall()!=[(1,)]:raise Rejected('journal_state')
        state=writer.read(db)
        if set(state)!={'schema','state','epoch','revision','committed','committed_digest','candidate'} or state!=target:raise Rejected('target_drift')
        if type(state['schema']) is not int or type(state['revision']) is not int or not 0<=state['revision']<2**63:raise Rejected('journal_state')
        if type(state['epoch']) is not str or not re.fullmatch('[0-9a-f]{32}',state['epoch']) or not re.fullmatch('[0-9a-f]{64}',state['committed_digest']):raise Rejected('journal_state')
        if state['state']=='READY' and state['candidate'] is not None:raise Rejected('journal_state')
        health=db.execute('SELECT id,state FROM health').fetchall()
        if health not in [[(1,'HEALTHY')],[(1,'STORAGE_FAILED')]]:raise Rejected('journal_health')
        rows=db.execute('SELECT id,digest,state,result,timing FROM requests LIMIT 65').fetchall()
        if len(rows)>64 or sum(r[2] in {'ACCEPTED','RUNNING','CANCEL_REQUESTED'} for r in rows)>1:raise Rejected('journal_capacity')
        allowed={'ACCEPTED','RUNNING','CANCEL_REQUESTED','COMMITTED','FAILED','DEGRADED','ROLLED_BACK','CANCELLED','EXPIRED','INTERRUPTED'}
        for identity,digest,status,result,timing in rows:
            if not re.fullmatch('[A-Za-z0-9_-]{1,64}',identity) or not re.fullmatch('[0-9a-f]{64}',digest) or status not in allowed:raise Rejected('journal_request')
            for value in [result,timing]:
                if value is not None and (type(value) is not str or len(value)>16384 or type(json.loads(value)) is not dict):raise Rejected('journal_request')
            if timing is not None:
                parsed=json.loads(timing)
                if set(parsed)!={'activation','recovery'}:raise Rejected('journal_timing')
                for budget in parsed.values():
                    if budget is not None:
                        if type(budget) is not dict or set(budget)!={'version','boot_id','accepted_boot_ns','expires_boot_ns','accepted_wall_ns','seconds'}:raise Rejected('journal_timing')
                        if type(budget['version']) is not int or budget['version']!=1 or type(budget['boot_id']) is not str or any(type(budget[k]) is not int for k in ['accepted_boot_ns','expires_boot_ns','accepted_wall_ns','seconds']):raise Rejected('journal_timing')
                        if not 1<=budget['seconds']<=10 or budget['expires_boot_ns']<=budget['accepted_boot_ns']:raise Rejected('journal_timing')
        if db.execute('SELECT id,length(value) FROM storage_probe').fetchall()!=[(1,64)]:raise Rejected('journal_probe')
        return health[0][1]
    except sqlite3.Error:deadlines.check();raise

def filesystem_probe(root,nonce,checkpoint):
    path=root/('verify-'+nonce);created=False;directory=None;owned=set()
    try:
        path.mkdir(mode=0o700);created=True;Writer.sync(root)
        directory=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        fd=os.open('before',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory);owned.add('before')
        with os.fdopen(fd,'wb') as f:f.write(os.urandom(4096));f.flush();os.fsync(f.fileno())
        deadlines.check();os.rename('before','after',src_dir_fd=directory,dst_dir_fd=directory);owned={'after'};os.fsync(directory)
        checkpoint('probe-written');deadlines.check()
        if set(os.listdir(directory))!=owned:raise Rejected('unknown_probe_files')
        os.unlink('after',dir_fd=directory);owned.clear();os.fsync(directory)
        os.close(directory);directory=None;path.rmdir();created=False;Writer.sync(root);deadlines.check()
    except Exception:
        # Preserve uncertain artifacts. Restart never guesses ownership or retries.
        raise
    finally:
        if directory is not None:os.close(directory)

def verify(config,identity,checkpoint=lambda point:None):
    store=RecoveryStore(Path(config['writer']['root']));row=store.get(identity)
    writer=Writer(**config['writer']);store.commit_checkpoint=lambda:checkpoint('verification-commit')
    try:
        row=store.begin(identity)
        with deadlines.use(row['timing']['budget']):
            checkpoint('validation-start');deadlines.check();require_authority(writer.root,row)
            with open(writer.root/'writer.lock','a+b') as lock:
                import fcntl
                fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
                with contextlib.closing(open_main(writer,config.get('sqlite_max_pages'))) as db:
                    health=validate_journal(db,writer,row['target']);checkpoint('journal-checked');deadlines.check()
                    filesystem_probe(writer.root,row['probe'],checkpoint)
                    db.execute('BEGIN IMMEDIATE');db.execute('UPDATE storage_probe SET value=? WHERE id=1',(os.urandom(64),));deadlines.check();db.commit();deadlines.check()
                    checkpoint('journal-written');health=validate_journal(db,writer,row['target']);require_authority(writer.root,row)
                    checkpoint('validation-finish');deadlines.check()
                    return store.finish(identity,'STORAGE_VERIFIED',{'storage_verified':True,'journal_verified':True,'prior_health':health,'updates_enabled':False,'restored':False})
    except Exception as error:
        try:deadlines.remaining(row['timing']['budget'])
        except deadlines.Expired:error=deadlines.Expired('verification_expired')
        state='EXPIRED' if isinstance(error,deadlines.Expired) else 'FAILED'
        return store.finish(identity,state,{'storage_verified':False,'updates_enabled':False,'restored':False,'error':type(error).__name__,'reason':str(error) if isinstance(error,(Rejected,deadlines.Expired)) else None,'sqlite_error':getattr(error,'sqlite_errorname',None),'errno':getattr(error,'errno',None)})
