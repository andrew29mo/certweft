"""Persisted opening intentions, pairing checks and shared admission guard."""
import contextlib,fcntl,json,os,re,sqlite3,stat
from pathlib import Path
from . import deadlines
from .core import Writer,Rejected
from .gate import Gate
from .operations import decision
from .recovery import RecoveryStore,open_main,require_authority,validate_journal
from .reconciliation import receipt,snapshot,digest


def text(value,pattern):return type(value) is str and re.fullmatch(pattern,value) is not None

def revision(value):return type(value) is int and 0<=value<2**63-1

def validate_binding(value):
    if type(value) is not dict or set(value)!={'preparation_request_id','receipt_digest','core_epoch','core_revision'}:raise Rejected('opening_binding')
    if not text(value['preparation_request_id'],r'[A-Za-z0-9_-]{1,64}') or not text(value['receipt_digest'],r'[0-9a-f]{64}') or not text(value['core_epoch'],r'[0-9a-f]{32}') or not revision(value['core_revision']):raise Rejected('opening_binding')
    return value

def validate_target(target):
    if type(target) is not dict or set(target)!={'preparation_request_id','receipt_digest','core_epoch','core_revision','journal_digest','degraded_references'}:raise Rejected('opening_target')
    validate_binding({k:target[k] for k in ['preparation_request_id','receipt_digest','core_epoch','core_revision']})
    refs=target['degraded_references']
    if not text(target['journal_digest'],r'[0-9a-f]{64}') or type(refs) is not dict or len(refs)>64:raise Rejected('opening_target')
    if any(not text(k,r'[A-Za-z0-9_-]{1,64}') or not text(v,r'[0-9a-f]{64}') for k,v in refs.items()):raise Rejected('opening_target')
    return target

@contextlib.contextmanager
def readonly(path):
    path=Path(path);st=path.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.geteuid() or st.st_mode & 0o077:raise Rejected('pair_file_permissions')
    db=sqlite3.connect(path.resolve().as_uri()+'?mode=ro',uri=True,timeout=deadlines.timeout(.2))
    try:yield db
    finally:db.close()

def require_updates(root,authority,main=None):
    """Shared entry/executor/COMMIT guard for bootstrap or fully paired recovery."""
    root=Path(root);Gate(root).require(authority)
    with readonly(root/'recovery.db') as catalog:
        if catalog.execute('SELECT version FROM recovery_meta').fetchall()!=[(2,)]:raise Rejected('recovery_schema')
        def check(db):
            owned=db.execute("SELECT 1 FROM sqlite_master WHERE name IN ('closed_reconciliation','opening_intent','release_preparation','admission_release') LIMIT 1").fetchone()
            if owned or catalog.execute('SELECT 1 FROM recovery_requests LIMIT 1').fetchone():
                from .admission import require_pair
                require_pair(db,catalog,Gate(root).read())
            # Untouched bootstrap remains the original enabled path.
        if main is None:
            with readonly(root/'journal.db') as db:check(db)
        else:check(main)
    Gate(root).require(authority)
    return True

def capture_pair(main,writer,catalog,gate,binding):
    validate_binding(binding)
    if gate['state']!='VERIFIED_CLOSED':raise Rejected('closed_gate_required')
    record=receipt(main)
    if record is None:raise Rejected('preparation_receipt_required')
    if record['gate']!=Gate.token(gate):raise Rejected('stale_preparation_gate')
    if record['request_id']!=binding['preparation_request_id'] or digest(record)!=binding['receipt_digest']:raise Rejected('preparation_binding_mismatch')
    prepared=RecoveryStore.row(catalog,binding['preparation_request_id']);proof=prepared['result']
    if prepared['kind']!='reconcile-closed' or prepared['state']!='JOURNAL_VERIFIED_CLOSED' or type(proof) is not dict:raise Rejected('completed_preparation_required')
    if record['request_digest']!=prepared['digest'] or record['certificate_request_id']!=prepared['target']['certificate_request_id']:raise Rejected('preparation_binding_mismatch')
    if proof.get('receipt_digest')!=digest(record) or proof.get('closed_gate')!=Gate.token(gate) or proof.get('journal_reconciled') is not True or proof.get('health_verified') is not True or proof.get('updates_enabled') is not False or proof.get('main_committed') is not True:raise Rejected('completed_preparation_required')
    core=writer.read(main);validate_journal(main,writer,core)
    if proof.get('committed')!=core['committed']:raise Rejected('preparation_binding_mismatch')
    if core!=record['core_after'] or (core['epoch'],core['revision'])!=(binding['core_epoch'],binding['core_revision']) or core['state']!='READY' or core['candidate'] is not None:raise Rejected('core_pair_mismatch')
    if main.execute('SELECT state,detail FROM health WHERE id=1').fetchone()!=('HEALTHY',None):raise Rejected('health_not_prepared')
    if main.execute("SELECT 1 FROM requests WHERE state IN ('ACCEPTED','RUNNING','CANCEL_REQUESTED')").fetchone():raise Rejected('normal_request_pending')
    degraded=main.execute("SELECT * FROM requests WHERE state='DEGRADED' ORDER BY id").fetchall()
    if [r[0] for r in degraded]!=record['resolved_degraded']:raise Rejected('unreferenced_degraded_history')
    journal_digest=digest(snapshot(main))
    if proof.get('after_digest')!=journal_digest:raise Rejected('preparation_journal_drift')
    return validate_target({**binding,'journal_digest':journal_digest,'degraded_references':{r[0]:digest(r) for r in degraded}})

def marker(db):
    schema=db.execute("SELECT type FROM sqlite_master WHERE name='opening_intent'").fetchone()
    if schema is None:return None
    if schema!=('table',) or [r[1] for r in db.execute('PRAGMA table_info(opening_intent)')]!=['id','record']:raise Rejected('opening_marker_schema')
    rows=db.execute('SELECT id,record FROM opening_intent LIMIT 2').fetchall()
    if len(rows)!=1 or rows[0][0]!=1 or type(rows[0][1]) is not str or len(rows[0][1])>4096:raise Rejected('opening_marker_schema')
    try:value=json.loads(rows[0][1])
    except (ValueError,UnicodeError):raise Rejected('opening_marker_schema')
    fields={'version','request_id','request_digest','target_digest','gate','preparation_request_id','receipt_digest','core_epoch','core_revision'}
    if type(value) is not dict or set(value)!=fields or type(value['version']) is not int or value['version']!=1:raise Rejected('opening_marker_schema')
    if not text(value['request_id'],r'[A-Za-z0-9_-]{1,64}') or any(not text(value[k],r'[0-9a-f]{64}') for k in ['request_digest','target_digest']):raise Rejected('opening_marker_schema')
    validate_binding({k:value[k] for k in ['preparation_request_id','receipt_digest','core_epoch','core_revision']})
    authority=value['gate']
    if type(authority) is not dict or set(authority)!={'gate_epoch','gate_revision'} or not text(authority['gate_epoch'],r'[0-9a-f]{32}') or not revision(authority['gate_revision']):raise Rejected('opening_marker_schema')
    if value['request_id']==value['preparation_request_id']:raise Rejected('opening_marker_schema')
    return value

def expected_marker(row):
    return {'version':1,'request_id':row['request_id'],'request_digest':row['digest'],'target_digest':digest(row['target']),'gate':row['timing']['authority'],**{k:row['target'][k] for k in ['preparation_request_id','receipt_digest','core_epoch','core_revision']}}

def check_pair(main,writer,catalog,row):
    require_authority(writer.root,row)
    target=row['target'];gate=Gate(writer.root).read()
    current=capture_pair(main,writer,catalog,gate,{k:target[k] for k in ['preparation_request_id','receipt_digest','core_epoch','core_revision']})
    if current!=target:raise Rejected('opening_target_drift')

def ready_closed(root,gate,store,checkpoint=lambda budget:None):
    if gate['state']!='VERIFIED_CLOSED':return False
    try:
        with readonly(Path(root)/'journal.db') as main,readonly(Path(root)/'recovery.db') as catalog:
            current=marker(main)
            if current is None:return False
            row=RecoveryStore.row(catalog,current['request_id'])
            if row['kind']!='prepare-opening' or row['state']!='OPENING_VERIFIED_CLOSED' or current!=expected_marker(row):return False
            deadlines.remaining(row['timing']['budget'])
            proof=row['result']
            if type(proof) is not dict or proof.get('marker_digest')!=digest(current) or proof.get('pair_verified') is not True or proof.get('degraded_references_verified') is not True or proof.get('degraded_reference_count')!=len(row['target']['degraded_references']) or proof.get('release_authorized') is not False or proof.get('updates_enabled') is not False:return False
            check_pair(main,Writer(root,'unused','unused','unused','unused','localhost','127.0.0.1',1),catalog,row)
            checkpoint(row['timing']['budget'])
            # Pair validation can consume the remaining budget. This function
            # has no CURRENT deadline context, so check this exact budget again.
            deadlines.remaining(row['timing']['budget'])
            return True
    except (Rejected,deadlines.Expired,sqlite3.Error,ValueError,KeyError,OSError):return False

def prepare_opening(config,identity,checkpoint=lambda point:None):
    store=RecoveryStore(Path(config['writer']['root']));row=store.get(identity);written=False;stage='admission';writer=Writer(**config['writer'])
    try:
        row=store.begin(identity)
        if row['kind']!='prepare-opening':raise Rejected('operation_kind')
        with deadlines.use(row['timing']['budget']):
            checkpoint('opening-start');require_authority(writer.root,row)
            with open(writer.root/'writer.lock','a+b') as lock:
                fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
                with contextlib.closing(open_main(writer,config.get('sqlite_max_pages'))) as main,readonly(writer.root/'recovery.db') as catalog:
                    stage='pair_validation';check_pair(main,writer,catalog,row);checkpoint('opening-validated');deadlines.check()
                    stage='marker_publication'
                    with decision(writer.root/'journal.db'):
                        main.execute('BEGIN IMMEDIATE')
                        try:
                            check_pair(main,writer,catalog,row);marker(main)
                            record=expected_marker(row)
                            main.execute('CREATE TABLE IF NOT EXISTS opening_intent(id INTEGER PRIMARY KEY CHECK(id=1),record TEXT NOT NULL)')
                            main.execute('INSERT OR REPLACE INTO opening_intent VALUES(1,?)',(json.dumps(record),))
                            checkpoint('opening-main-commit');check_pair(main,writer,catalog,row);deadlines.check();main.commit();written=True
                        except Exception:main.rollback();raise
                    checkpoint('opening-main-committed');deadlines.check();stage='result_publication'
                    def final_check():
                        checkpoint('opening-result-commit');check_pair(main,writer,catalog,row)
                        if marker(main)!=record:raise Rejected('stale_opening_marker')
                    store.commit_checkpoint=final_check
                    return store.finish(identity,'OPENING_VERIFIED_CLOSED',{'pair_verified':True,'degraded_references_verified':True,'degraded_reference_count':len(row['target']['degraded_references']),'marker_digest':digest(record),'updates_enabled':False,'release_authorized':False})
    except Exception as error:
        try:deadlines.remaining(row['timing']['budget'])
        except deadlines.Expired:error=deadlines.Expired('opening_expired')
        return store.finish(identity,'EXPIRED' if isinstance(error,deadlines.Expired) else 'FAILED',{'pair_verified':False,'updates_enabled':False,'release_authorized':False,'marker_commit_observed':written,'marker_commit_may_have_happened':stage in {'marker_publication','result_publication'},'failure_stage':stage,'error':type(error).__name__,'reason':str(error) if isinstance(error,(Rejected,deadlines.Expired)) else None,'sqlite_error':getattr(error,'sqlite_errorname',None),'errno':getattr(error,'errno',None)})
