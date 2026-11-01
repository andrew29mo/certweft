"""Explicit root reopening. Three durable records qualify one live session.

A RUNNING Gate alone is not permission. Startup always fences an unclean session;
no pending reopening is replayed. Historical failure rows remain immutable.
"""
import contextlib,fcntl,json,os,sqlite3,stat,time
from pathlib import Path
from . import deadlines
from .core import Rejected
from .executor import FixedWriter
from .gate import Gate
from .operations import decision
from .recovery import RecoveryStore,open_main,filesystem_probe
from .reconciliation import digest,snapshot
from .opening import readonly,text
from . import release

def validate_binding(b):
    if type(b) is not dict or set(b)!={'release_request_id','release_receipt_digest'} or not text(b['release_request_id'],r'[A-Za-z0-9_-]{1,64}') or not text(b['release_receipt_digest'],r'[0-9a-f]{64}'):raise Rejected('admission_binding')
    return b

def validate_target(t):
    if type(t) is not dict or set(t)!={'release_request_id','release_receipt_digest','release_digest','release_budget','release_target'}:raise Rejected('admission_target')
    validate_binding({k:t[k] for k in ['release_request_id','release_receipt_digest']})
    if not text(t['release_digest'],r'[0-9a-f]{64}'):raise Rejected('admission_target')
    release.validate_target(t['release_target'])
    # Reuse the exact budget schema validator; never replace stored deadlines.
    release.validate_target({**t['release_target'],'source_budget':t['release_budget']})
    return t

def effective_budget(row):
    budgets=[row['timing']['budget'],row['target']['release_budget'],row['target']['release_target']['source_budget']]
    for b in budgets:deadlines.remaining(b)
    return {**budgets[0],'expires_boot_ns':min(b['expires_boot_ns'] for b in budgets)}

def capture_source(main,writer,catalog,gate,binding):
    validate_binding(binding)
    r=RecoveryStore.row(catalog,binding['release_request_id']);p=r['result'];record=release.receipt(main)
    if r['kind']!='prepare-release' or r['state']!='RELEASE_VERIFIED_CLOSED' or type(p) is not dict:raise Rejected('completed_release_required')
    if record!=release.expected_receipt(r,p.get('fingerprint'),p.get('committed')) or digest(record)!=binding['release_receipt_digest'] or p.get('receipt_digest')!=digest(record):raise Rejected('release_pair_mismatch')
    if any(p.get(k) is not True for k in ['storage_verified','certificate_verified','tls_confirmed']) or p.get('updates_enabled') is not False or p.get('release_authorized') is not False:raise Rejected('completed_release_required')
    release.check_source(main,writer,catalog,r)
    return validate_target({**binding,'release_digest':r['digest'],'release_budget':r['timing']['budget'],'release_target':r['target']})

def expected(row):
    a=row['timing']['authority'];g={'gate_epoch':a['gate_epoch'],'gate_revision':a['gate_revision']+1}
    return {'version':1,'request_id':row['request_id'],'request_digest':row['digest'],'target_digest':digest(row['target']),'gate':g,'degraded_references':row['target']['release_target']['opening_target']['degraded_references']}

def record(db):
    schema=db.execute("SELECT type FROM sqlite_master WHERE name='admission_release'").fetchone()
    if schema is None:return None
    if schema!=('table',) or [r[1] for r in db.execute('PRAGMA table_info(admission_release)')]!=['id','record']:raise Rejected('admission_schema')
    rows=db.execute('SELECT id,record FROM admission_release LIMIT 2').fetchall()
    if len(rows)!=1 or rows[0][0]!=1 or type(rows[0][1]) is not str or len(rows[0][1])>16384:raise Rejected('admission_schema')
    try:r=json.loads(rows[0][1])
    except (ValueError,UnicodeError):raise Rejected('admission_schema')
    if type(r) is not dict or set(r)!={'version','request_id','request_digest','target_digest','gate','degraded_references'} or type(r['version']) is not int or r['version']!=1 or not text(r['request_id'],r'[A-Za-z0-9_-]{1,64}'):raise Rejected('admission_schema')
    if any(not text(r[k],r'[0-9a-f]{64}') for k in ['request_digest','target_digest']):raise Rejected('admission_schema')
    g=r['gate'];refs=r['degraded_references']
    if type(g) is not dict or set(g)!={'gate_epoch','gate_revision'} or not text(g['gate_epoch'],r'[0-9a-f]{32}') or type(g['gate_revision']) is not int or not 0<=g['gate_revision']<2**63-1:raise Rejected('admission_schema')
    if type(refs) is not dict or len(refs)>64 or any(not text(k,r'[A-Za-z0-9_-]{1,64}') or not text(v,r'[0-9a-f]{64}') for k,v in refs.items()):raise Rejected('admission_schema')
    return r

def references(db,refs):
    current={r[0]:digest(r) for r in db.execute("SELECT * FROM requests WHERE state='DEGRADED' ORDER BY id")}
    if current!=refs:raise Rejected('unresolved_degraded_history')

def require_pair(main,catalog,gate):
    r=record(main)
    if r is None or gate['state']!='RUNNING' or r['gate']!=Gate.token(gate):raise Rejected('opening_handoff_required')
    row=RecoveryStore.row(catalog,r['request_id']);p=row['result']
    if row['kind']!='open-updates' or row['state']!='OPENED' or r!=expected(row) or type(p) is not dict or p.get('admission_digest')!=digest(r) or p.get('opened_gate')!=Gate.token(gate) or any(p.get(k) is not True for k in ['storage_verified','tls_confirmed','updates_enabled']):raise Rejected('opening_handoff_required')
    # Successful admission outlives its *operation* deadline, within this session.
    # It never exempts a newer/changed DEGRADED row or a storage fault.
    references(main,r['degraded_references'])
    if main.execute('SELECT state,detail FROM health WHERE id=1').fetchone()!=('HEALTHY',None):raise Rejected('storage_unavailable')
    return r

def open_updates(config,identity,checkpoint=lambda point:None):
    root=Path(config['writer']['root']);store=RecoveryStore(root);row=store.get(identity);published=None;written=False;stage='admission'
    writer=FixedWriter(**config['writer']);writer.master=config['master']
    try:
        row=store.begin(identity)
        with deadlines.use(effective_budget(row)):
            checkpoint('admission-start')
            for k in ['key','conf','ca']:
                s=Path(config['writer'][k]).lstat()
                if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_mode & 0o022:raise Rejected('target_permissions')
            with open(root/'writer.lock','a+b') as lock:
                fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
                with contextlib.closing(open_main(writer,config.get('sqlite_max_pages'))) as main,readonly(root/'recovery.db') as catalog:
                    def check(closed=True):
                        deadlines.remaining(effective_budget(row));g=Gate(root).read()
                        if closed:
                            if Gate.token(g)!=row['timing']['authority']:raise Rejected('stale_gate_authority')
                            current=capture_source(main,writer,catalog,g,{k:row['target'][k] for k in ['release_request_id','release_receipt_digest']})
                            if current!=row['target']:raise Rejected('admission_source_drift')
                        else:
                            if g!=published:raise Rejected('stale_gate_authority')
                            source=RecoveryStore.row(catalog,row['target']['release_request_id'])
                            if source['state']!='RELEASE_VERIFIED_CLOSED' or source['digest']!=row['target']['release_digest'] or source['target']!=row['target']['release_target'] or source['timing']['budget']!=row['target']['release_budget'] or release.receipt(main)!=release.expected_receipt(source,source['result']['fingerprint'],source['result']['committed']):raise Rejected('admission_source_drift')
                            from .opening import marker,expected_marker
                            opening=RecoveryStore.row(catalog,source['target']['opening_request_id'])
                            if opening['state']!='OPENING_VERIFIED_CLOSED' or marker(main)!=expected_marker(opening):raise Rejected('admission_source_drift')
                            if digest(snapshot(main))!=source['target']['opening_target']['journal_digest']:raise Rejected('admission_journal_drift')
                        deadlines.check()
                    def probe():
                        filesystem_probe(root,row['probe'],checkpoint)
                        main.execute('BEGIN IMMEDIATE')
                        try:main.execute('UPDATE storage_probe SET value=? WHERE id=1',(os.urandom(64),));deadlines.check();main.commit();deadlines.check()
                        except Exception:main.rollback();raise
                    stage='storage_validation';check();probe();checkpoint('admission-storage-verified');check()
                    name=writer.read(main)['committed'];stage='tls_confirmation';fp=writer.check(name)
                    if os.readlink(root/'active.conf')!='v-'+name+'/tls.conf':raise Rejected('committed_pointer_required')
                    if writer.confirm(name,time.monotonic()+5)!=fp or writer.check(name)!=fp:raise Rejected('wire_certificate')
                    checkpoint('admission-confirmed');check();r=expected(row)
                    stage='journal_publication'
                    with decision(root/'journal.db'):
                        main.execute('BEGIN IMMEDIATE')
                        try:
                            check();record(main)
                            main.execute('CREATE TABLE IF NOT EXISTS admission_release(id INTEGER PRIMARY KEY CHECK(id=1),record TEXT NOT NULL)')
                            main.execute('INSERT OR REPLACE INTO admission_release VALUES(1,?)',(json.dumps(r),))
                            checkpoint('admission-main-commit');check();main.commit();written=True
                        except Exception:main.rollback();raise
                    checkpoint('admission-main-committed');check();stage='gate_publication'
                    # Root terminal COMMIT is the final permission boundary. Both
                    # earlier records are inert until it succeeds under the barrier.
                    with store.transaction(lambda:final()) as db:
                        current=store.row(db,identity)
                        if current['state']!='RUNNING' or current['digest']!=row['digest']:raise Rejected('stale_admission_operation')
                        check();old=Gate(root).read()
                        published={**old,'revision':old['revision']+1,'state':'RUNNING','reason':'operator_opened'}
                        checkpoint('admission-gate-write');check();Gate(root).write(published)
                        checkpoint('admission-gate-published');stage='result_publication'
                        result={'storage_verified':True,'tls_confirmed':True,'committed':name,'fingerprint':fp,'admission_digest':digest(r),'opened_gate':Gate.token(published),'updates_enabled':True}
                        db.execute("UPDATE recovery_requests SET state='OPENED',result=? WHERE id=?",(json.dumps(result),identity))
                        def final():
                            checkpoint('admission-result-commit');check(False)
                            if record(main)!=r:raise Rejected('stale_admission_record')
                            probe();check(False)
                            if writer.check(name)!=fp:raise Rejected('certificate_drift')
                            check(False)
                        completed=store.row(db,identity)
                    checkpoint('admission-result-committed');check(False)
                    return completed
    except Exception as error:
        # Never overwrite a newer Gate. A failed/pending final SQL row also makes
        # a published RUNNING marker unusable, including uncertain fsync results.
        if published is not None:
            try:
                with decision(root/'journal.db'):
                    g=Gate(root).read()
                    if g==published:Gate(root).write({**g,'revision':g['revision']+1,'state':'RECOVERY_REQUIRED','reason':'unclean_or_blocked'})
            except Exception:pass
        try:deadlines.remaining(effective_budget(row))
        except deadlines.Expired:error=deadlines.Expired('admission_or_source_expired')
        failed=store.finish(identity,'EXPIRED' if isinstance(error,deadlines.Expired) else 'FAILED',{'updates_enabled':False,'journal_commit_observed':written,'failure_stage':stage,'error':type(error).__name__,'reason':str(error) if isinstance(error,(Rejected,deadlines.Expired)) else None,'errno':getattr(error,'errno',None),'sqlite_error':getattr(error,'sqlite_errorname',None)})
        if failed['state']=='OPENED':raise Rejected('opening_result_uncertain') from error
        return failed
