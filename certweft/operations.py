"""Short durable transactions shared by ingress, cancellation and final commit."""
import hashlib,json,re,sqlite3
from contextlib import contextmanager
from .core import Rejected
from . import deadlines
LIVE=('ACCEPTED','RUNNING','CANCEL_REQUESTED')

class Cancelled(Rejected):pass

class Operations:
    def __init__(self,root):self.path=str(root/'journal.db')
    @contextmanager
    def transaction(self):
        db=sqlite3.connect(self.path,timeout=.5)
        try:
            db.execute('PRAGMA synchronous=FULL');db.execute('BEGIN IMMEDIATE')
            yield db;db.commit()
        except Exception:db.rollback();raise
        finally:db.close()
    def initialize(self):
        with self.transaction() as db:
            db.execute('CREATE TABLE IF NOT EXISTS requests (id TEXT PRIMARY KEY, digest TEXT NOT NULL, state TEXT NOT NULL, result TEXT)')
            if 'timing' not in [row[1] for row in db.execute('PRAGMA table_info(requests)')]:db.execute('ALTER TABLE requests ADD COLUMN timing TEXT')
            db.execute("CREATE UNIQUE INDEX IF NOT EXISTS one_live_request ON requests((1)) WHERE state IN ('ACCEPTED','RUNNING','CANCEL_REQUESTED')")
    @staticmethod
    def identity(body):
        if set(body)-{'timeout_seconds'}!={'op','request_id','certificate','epoch','revision'} or body['op']!='submit':raise Rejected('request_shape')
        if type(body['request_id']) is not str or not re.fullmatch('[A-Za-z0-9_-]{1,64}',body['request_id']):raise Rejected('request_id')
        if type(body['certificate']) is not str or len(body['certificate'].encode())>32768:raise Rejected('certificate_budget')
        if type(body['epoch']) is not str or type(body['revision']) is not int:raise Rejected('authority_shape')
        if type(body.get('timeout_seconds',10)) is not int or not 1<=body.get('timeout_seconds',10)<=10:raise Rejected('timeout_policy')
        return hashlib.sha256(json.dumps({k:v for k,v in body.items() if k!='request_id'},sort_keys=True,separators=(',',':')).encode()).hexdigest()
    @staticmethod
    def row(db,identity):
        row=db.execute('SELECT digest,state,result,timing FROM requests WHERE id=?',(identity,)).fetchone()
        if row is None:raise Rejected('unknown_request')
        return {'request_id':identity,'digest':row[0],'state':row[1],'result':json.loads(row[2]) if row[2] else None,'timing':json.loads(row[3]) if row[3] else None}
    def get(self,identity):
        with self.transaction() as db:return self.row(db,identity)
    def admit(self,body):
        digest=self.identity(body);identity=body['request_id']
        with self.transaction() as db:
            existing=db.execute('SELECT digest FROM requests WHERE id=?',(identity,)).fetchone()
            if existing:
                if existing[0]!=digest:raise Rejected('request_conflict')
                return self.row(db,identity),False
            if db.execute("SELECT 1 FROM requests WHERE state='DEGRADED'").fetchone():raise Rejected('degraded')
            if db.execute('SELECT count(*) FROM requests').fetchone()[0]>=64:raise Rejected('history_full')
            if db.execute("SELECT 1 FROM requests WHERE state IN ('ACCEPTED','RUNNING','CANCEL_REQUESTED')").fetchone():raise Rejected('busy')
            timing={'activation':deadlines.create(body.get('timeout_seconds',10)),'recovery':None}
            db.execute('INSERT INTO requests(id,digest,state,result,timing) VALUES(?,?,?,NULL,?)',(identity,digest,'ACCEPTED',json.dumps(timing)))
            return self.row(db,identity),True
    def cancel(self,identity):
        with self.transaction() as db:
            row=self.row(db,identity)
            if row['state'] in LIVE:db.execute("UPDATE requests SET state='CANCEL_REQUESTED' WHERE id=?",(identity,))
            return self.row(db,identity)
    def begin(self,identity):
        with self.transaction() as db:
            row=self.row(db,identity)
            if row['state']=='CANCEL_REQUESTED':
                db.execute("UPDATE requests SET state='CANCELLED' WHERE id=?",(identity,));return False
            if row['state']!='ACCEPTED':raise Rejected('not_accepted')
            try:deadlines.remaining(row['timing']['activation'] if row['timing'] else {'version':0})
            except deadlines.Expired:
                db.execute("UPDATE requests SET state='EXPIRED' WHERE id=?",(identity,));return False
            db.execute("UPDATE requests SET state='RUNNING' WHERE id=?",(identity,));return True
    def recovery_budget(self,identity):
        with self.transaction() as db:
            row=self.row(db,identity);timing=row['timing'] or {'activation':None,'recovery':None}
            activation=timing.get('activation')
            if activation and activation.get('boot_id')==deadlines.boot_id():deadlines.clock_valid(activation)
            if timing['recovery'] is None:
                timing['recovery']=deadlines.create(5)
                db.execute('UPDATE requests SET timing=? WHERE id=?',(json.dumps(timing),identity))
            return timing['recovery']
    def check_cancel(self,identity):
        if self.get(identity)['state']=='CANCEL_REQUESTED':raise Cancelled('cancel_requested')
    def finish(self,identity,state,result):
        with self.transaction() as db:
            current=self.row(db,identity)
            if current['state'] not in LIVE:return current
            db.execute('UPDATE requests SET state=?,result=? WHERE id=?',(state,json.dumps(result),identity))
            return self.row(db,identity)
    def pending(self):
        with self.transaction() as db:return [r[0] for r in db.execute("SELECT id FROM requests WHERE state IN ('ACCEPTED','RUNNING','CANCEL_REQUESTED')")]
    @staticmethod
    def commit(db,identity,state):
        # Same SQLite transaction commits the selected version and request outcome.
        db.execute('BEGIN IMMEDIATE')
        row=db.execute('SELECT state,timing FROM requests WHERE id=?',(identity,)).fetchone()
        if row is None or row[0]!='RUNNING':raise Cancelled('commit_not_authorized')
        timing=json.loads(row[1]) if row[1] else None
        if timing:deadlines.remaining(timing['activation'])
        db.execute('INSERT OR REPLACE INTO state VALUES(1,?)',(json.dumps(state),))
        db.execute("UPDATE requests SET state='COMMITTED',result=? WHERE id=?",(json.dumps({'committed':state['committed']}),identity))
        if timing:deadlines.remaining(timing['activation'])
        db.commit()
