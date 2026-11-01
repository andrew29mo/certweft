"""Fresh journal/health preparation. Never opens Gate or reloads Nginx."""
import contextlib,fcntl,hashlib,json,os,sqlite3,stat,time,uuid
from pathlib import Path
from . import deadlines
from .core import Rejected
from .executor import FixedWriter
from .gate import Gate
from .operations import decision
from .recovery import RecoveryStore,require_authority,open_main,validate_journal,filesystem_probe


def digest(value):return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()

def snapshot(db):
    return {name:db.execute('SELECT * FROM '+name+' ORDER BY id').fetchall() for name in ['state','health','requests']}

def capture_target(db,writer,core,certificate,gate):
    proof=certificate['result']
    if certificate['kind']!='recover-certificate' or certificate['state']!='VERIFIED_CLOSED' or type(proof) is not dict or proof.get('closed_gate')!=Gate.token(gate):raise Rejected('certificate_completion_required')
    if proof.get('committed')!=core['committed'] or certificate['target'].get('committed_digest')!=core['committed_digest'] or not proof.get('restored') or not proof.get('tls_confirmed'):raise Rejected('certificate_target_mismatch')
    validate_journal(db,writer,core)
    return {'core':core,'journal_digest':digest(snapshot(db)),'certificate_request_id':certificate['request_id']}

def receipt(db):
    if db.execute("SELECT type FROM sqlite_master WHERE name='closed_reconciliation'").fetchone() is None:return None
    if db.execute("SELECT type FROM sqlite_master WHERE name='closed_reconciliation'").fetchone()!=('table',) or [r[1] for r in db.execute('PRAGMA table_info(closed_reconciliation)')]!=['id','record']:raise Rejected('reconciliation_schema')
    rows=db.execute('SELECT id,record FROM closed_reconciliation LIMIT 2').fetchall()
    if len(rows)!=1 or rows[0][0]!=1 or type(rows[0][1]) is not str or len(rows[0][1])>16384:raise Rejected('reconciliation_schema')
    value=json.loads(rows[0][1])
    fields={'version','request_id','request_digest','gate','certificate_request_id','committed','prior_journal_digest','core_after','interrupted','resolved_degraded'}
    if type(value) is not dict or set(value)!=fields or type(value['version']) is not int or value['version']!=1 or type(value['core_after']) is not dict or type(value['gate']) is not dict or type(value['interrupted']) is not list or type(value['resolved_degraded']) is not list:raise Rejected('reconciliation_schema')
    return value

def completion_recorded(root,gate,store):
    if gate['state']!='VERIFIED_CLOSED':return False
    try:
        with contextlib.closing(sqlite3.connect((Path(root)/'journal.db').resolve().as_uri()+'?mode=ro',uri=True,timeout=.2)) as db:
            record=receipt(db)
            if record is None or record.get('gate')!=Gate.token(gate):return False
            row=store.get(record['request_id']);result=row['result']
            return row['kind']=='reconcile-closed' and row['state']=='JOURNAL_VERIFIED_CLOSED' and type(result) is dict and result.get('receipt_digest')==digest(record) and result.get('after_digest')==digest(snapshot(db)) and result.get('closed_gate')==Gate.token(gate) and result.get('updates_enabled') is False
    except (Rejected,sqlite3.Error,ValueError,KeyError,OSError):return False

def reconcile_main(db,writer,row,checkpoint):
    """One main-journal transaction; proof and admission remain separate/closed."""
    target=row['target'];core=target['core']
    with decision(writer.root/'journal.db'):
        db.execute('BEGIN IMMEDIATE')
        try:
            require_authority(writer.root,row);validate_journal(db,writer,core)
            if digest(snapshot(db))!=target['journal_digest']:raise Rejected('journal_drift')
            if os.readlink(writer.root/'active.conf')!='v-'+core['committed']+'/tls.conf':raise Rejected('committed_pointer_required')
            receipt(db) # Reject an unknown/malformed preexisting receipt instead of replacing it.
            if core['revision']>=2**63-2:raise Rejected('revision_exhausted')
            after={**core,'state':'READY','candidate':None,'epoch':uuid.uuid4().hex,'revision':core['revision']+1}
            live=db.execute("SELECT id,state FROM requests WHERE state IN ('ACCEPTED','RUNNING','CANCEL_REQUESTED') ORDER BY id").fetchall()
            degraded=[r[0] for r in db.execute("SELECT id FROM requests WHERE state='DEGRADED' ORDER BY id")]
            for identity,prior in live:
                result={'reconciled_closed':True,'prior_state':prior,'execution_outcome':'unknown','committed':core['committed'],'recovery_request_id':row['request_id'],'updates_enabled':False}
                db.execute("UPDATE requests SET state='INTERRUPTED',result=? WHERE id=?",(json.dumps(result),identity))
            db.execute('UPDATE state SET data=? WHERE id=1',(json.dumps(after),))
            db.execute("UPDATE health SET state='HEALTHY',detail=NULL WHERE id=1")
            record={'version':1,'request_id':row['request_id'],'request_digest':row['digest'],'gate':row['timing']['authority'],'certificate_request_id':target['certificate_request_id'],'committed':core['committed'],'prior_journal_digest':target['journal_digest'],'core_after':after,'interrupted':live,'resolved_degraded':degraded}
            db.execute('CREATE TABLE IF NOT EXISTS closed_reconciliation(id INTEGER PRIMARY KEY CHECK(id=1),record TEXT NOT NULL)')
            db.execute('INSERT OR REPLACE INTO closed_reconciliation VALUES(1,?)',(json.dumps(record),))
            checkpoint('reconcile-main-commit');require_authority(writer.root,row);deadlines.check()
            db.commit()
            return record,digest(snapshot(db))
        except Exception:db.rollback();raise

def reconcile_closed(config,identity,checkpoint=lambda point:None):
    store=RecoveryStore(Path(config['writer']['root']));row=store.get(identity);main_committed=False;stage='admission'
    store.commit_checkpoint=lambda:checkpoint('reconcile-result-commit')
    writer=FixedWriter(**config['writer']);writer.master=config['master']
    try:
        row=store.begin(identity)
        if row['kind']!='reconcile-closed':raise Rejected('operation_kind')
        with deadlines.use(row['timing']['budget']):
            stage='storage_validation';checkpoint('reconcile-start');require_authority(writer.root,row)
            for field in ['key','conf','ca']:
                st=Path(config['writer'][field]).lstat()
                if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_mode & 0o022:raise Rejected('target_permissions')
            with open(writer.root/'writer.lock','a+b') as lock:
                fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
                with contextlib.closing(open_main(writer,config.get('sqlite_max_pages'))) as db:
                    core=row['target']['core'];prior_health=validate_journal(db,writer,core)
                    if digest(snapshot(db))!=row['target']['journal_digest']:raise Rejected('journal_drift')
                    filesystem_probe(writer.root,row['probe'],checkpoint)
                    db.execute('BEGIN IMMEDIATE');db.execute('UPDATE storage_probe SET value=? WHERE id=1',(os.urandom(64),));deadlines.check();db.commit();deadlines.check()
                    stage='certificate_validation';name=core['committed'];expected=writer.check(name)
                    if os.readlink(writer.root/'active.conf')!='v-'+name+'/tls.conf':raise Rejected('committed_pointer_required')
                    stage='tls_confirmation';observed=writer.confirm(name,time.monotonic()+5)
                    if observed!=expected or writer.check(name)!=expected:raise Rejected('target_drift')
                    stage='journal_reconciliation';checkpoint('reconcile-validated');deadlines.check()
                    record,after_digest=reconcile_main(db,writer,row,checkpoint);main_committed=True
                    checkpoint('reconcile-main-committed');deadlines.check();require_authority(writer.root,row)
                    stage='result_publication'
                    def final_check():
                        checkpoint('reconcile-result-commit')
                        validate_journal(db,writer,record['core_after'])
                        if digest(snapshot(db))!=after_digest or digest(receipt(db))!=digest(record):raise Rejected('journal_drift')
                    store.commit_checkpoint=final_check
                    proof={'journal_reconciled':True,'health_verified':True,'prior_health':prior_health,'receipt_digest':digest(record),'after_digest':after_digest,'closed_gate':row['timing']['authority'],'committed':name,'fingerprint':expected,'updates_enabled':False,'main_committed':True}
                    return store.finish(identity,'JOURNAL_VERIFIED_CLOSED',proof)
    except Exception as error:
        try:deadlines.remaining(row['timing']['budget'])
        except deadlines.Expired:error=deadlines.Expired('reconciliation_expired')
        # A returned COMMIT error is uncertain, not proof that the tx did not persist.
        return store.finish(identity,'EXPIRED' if isinstance(error,deadlines.Expired) else 'FAILED',{'journal_reconciled':False,'health_verified':False,'updates_enabled':False,'main_commit_observed':main_committed,'main_commit_may_have_happened':stage in {'journal_reconciliation','result_publication'},'failure_stage':stage,'error':type(error).__name__,'reason':str(error) if isinstance(error,(Rejected,deadlines.Expired)) else None,'sqlite_error':getattr(error,'sqlite_errorname',None),'errno':getattr(error,'errno',None)})
