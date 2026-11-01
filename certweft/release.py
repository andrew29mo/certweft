"""Fresh release evidence and paired receipt. Admission deliberately stays closed."""
import contextlib,fcntl,json,os,re,sqlite3,stat,time
from pathlib import Path
from . import deadlines
from .core import Writer,Rejected
from .executor import FixedWriter
from .gate import Gate
from .operations import decision
from .recovery import RecoveryStore,open_main,require_authority,filesystem_probe
from .reconciliation import digest
from .opening import text,validate_target as opening_target,marker as opening_marker,expected_marker as expected_opening,check_pair,readonly

def validate_binding(value):
    if type(value) is not dict or set(value)!={'opening_request_id','opening_marker_digest'} or not text(value['opening_request_id'],r'[A-Za-z0-9_-]{1,64}') or not text(value['opening_marker_digest'],r'[0-9a-f]{64}'):raise Rejected('release_binding')
    return value

def validate_target(value):
    fields={'opening_request_id','opening_marker_digest','source_request_digest','source_budget','opening_target'}
    if type(value) is not dict or set(value)!=fields:raise Rejected('release_target')
    validate_binding({k:value[k] for k in ['opening_request_id','opening_marker_digest']});opening_target(value['opening_target'])
    if not text(value['source_request_digest'],r'[0-9a-f]{64}'):raise Rejected('release_target')
    b=value['source_budget'];keys={'version','boot_id','accepted_boot_ns','expires_boot_ns','accepted_wall_ns','seconds'}
    if type(b) is not dict or set(b)!=keys or any(type(b[k]) is not int for k in keys-{'boot_id'}):raise Rejected('release_source_budget')
    if b['version']!=1 or not 1<=b['seconds']<=10 or not text(b['boot_id'],r'[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}'):raise Rejected('release_source_budget')
    if any(not 0<=b[k]<2**63 for k in ['accepted_boot_ns','expires_boot_ns','accepted_wall_ns']) or b['expires_boot_ns']-b['accepted_boot_ns']!=b['seconds']*10**9:raise Rejected('release_source_budget')
    return value

def effective_budget(row):
    """Neither stored clock is reset; timeout contexts use their earlier expiry."""
    own=row['timing']['budget'];source=row['target']['source_budget']
    deadlines.remaining(own);deadlines.remaining(source)
    merged={**own,'expires_boot_ns':min(own['expires_boot_ns'],source['expires_boot_ns'])}
    deadlines.remaining(merged);return merged

def capture_source(main,writer,catalog,gate,binding):
    validate_binding(binding)
    if gate['state']!='VERIFIED_CLOSED':raise Rejected('closed_gate_required')
    source=RecoveryStore.row(catalog,binding['opening_request_id']);proof=source['result']
    if source['kind']!='prepare-opening' or source['state']!='OPENING_VERIFIED_CLOSED' or type(proof) is not dict:raise Rejected('completed_opening_required')
    current=opening_marker(main)
    if current is None or current!=expected_opening(source) or digest(current)!=binding['opening_marker_digest']:raise Rejected('opening_source_mismatch')
    if proof.get('marker_digest')!=digest(current) or proof.get('pair_verified') is not True or proof.get('degraded_references_verified') is not True or type(proof.get('degraded_reference_count')) is not int or proof['degraded_reference_count']!=len(source['target']['degraded_references']) or proof.get('updates_enabled') is not False or proof.get('release_authorized') is not False:raise Rejected('completed_opening_required')
    check_pair(main,writer,catalog,source);deadlines.remaining(source['timing']['budget'])
    return validate_target({**binding,'source_request_digest':source['digest'],'source_budget':source['timing']['budget'],'opening_target':source['target']})

def check_source(main,writer,catalog,row):
    require_authority(writer.root,row);effective_budget(row)
    bound=row['target'];current=capture_source(main,writer,catalog,Gate(writer.root).read(),{k:bound[k] for k in ['opening_request_id','opening_marker_digest']})
    if current!=bound:raise Rejected('release_source_drift')
    effective_budget(row)

def expected_receipt(row,fingerprint,committed):
    return {'version':1,'request_id':row['request_id'],'request_digest':row['digest'],'target_digest':digest(row['target']),'gate':row['timing']['authority'],'opening_request_id':row['target']['opening_request_id'],'opening_marker_digest':row['target']['opening_marker_digest'],'committed':committed,'fingerprint':fingerprint,'updates_enabled':False,'release_authorized':False}

def receipt(main):
    schema=main.execute("SELECT type FROM sqlite_master WHERE name='release_preparation'").fetchone()
    if schema is None:return None
    if schema!=('table',) or [r[1] for r in main.execute('PRAGMA table_info(release_preparation)')]!=['id','record']:raise Rejected('release_receipt_schema')
    values=main.execute('SELECT id,record FROM release_preparation LIMIT 2').fetchall()
    if len(values)!=1 or values[0][0]!=1 or type(values[0][1]) is not str or len(values[0][1])>4096:raise Rejected('release_receipt_schema')
    try:r=json.loads(values[0][1])
    except (ValueError,UnicodeError):raise Rejected('release_receipt_schema')
    fields={'version','request_id','request_digest','target_digest','gate','opening_request_id','opening_marker_digest','committed','fingerprint','updates_enabled','release_authorized'}
    if type(r) is not dict or set(r)!=fields or type(r['version']) is not int or r['version']!=1 or r['updates_enabled'] is not False or r['release_authorized'] is not False:raise Rejected('release_receipt_schema')
    if any(not text(r[k],r'[A-Za-z0-9_-]{1,64}') for k in ['request_id','opening_request_id']) or r['request_id']==r['opening_request_id']:raise Rejected('release_receipt_schema')
    if any(not text(r[k],r'[0-9a-f]{64}') for k in ['request_digest','target_digest','opening_marker_digest','fingerprint']) or not text(r['committed'],r'[0-9a-f]{32}'):raise Rejected('release_receipt_schema')
    g=r['gate']
    if type(g) is not dict or set(g)!={'gate_epoch','gate_revision'} or not text(g['gate_epoch'],r'[0-9a-f]{32}') or type(g['gate_revision']) is not int or not 0<=g['gate_revision']<2**63-1:raise Rejected('release_receipt_schema')
    return r

def ready_closed(root,gate):
    if gate['state']!='VERIFIED_CLOSED':return False
    try:
        with readonly(Path(root)/'journal.db') as main,readonly(Path(root)/'recovery.db') as catalog:
            current=receipt(main)
            if current is None:return False
            row=RecoveryStore.row(catalog,current['request_id']);proof=row['result']
            if row['kind']!='prepare-release' or row['state']!='RELEASE_VERIFIED_CLOSED' or type(proof) is not dict:return False
            if current!=expected_receipt(row,proof.get('fingerprint'),proof.get('committed')) or proof.get('receipt_digest')!=digest(current):return False
            if any(proof.get(k) is not True for k in ['storage_verified','certificate_verified','tls_confirmed']) or proof.get('updates_enabled') is not False or proof.get('release_authorized') is not False:return False
            writer=Writer(root,'unused','unused','unused','unused','localhost','127.0.0.1',1)
            check_source(main,writer,catalog,row)
            if writer.read(main)['committed']!=current['committed']:return False
            deadlines.remaining(effective_budget(row));return True
    except (Rejected,deadlines.Expired,sqlite3.Error,ValueError,KeyError,OSError):return False

def prepare_release(config,identity,checkpoint=lambda point:None):
    root=Path(config['writer']['root']);store=RecoveryStore(root);row=store.get(identity);written=False;storage_done=False;tls_done=False;stage='admission'
    writer=FixedWriter(**config['writer']);writer.master=config['master']
    try:
        row=store.begin(identity)
        if row['kind']!='prepare-release':raise Rejected('operation_kind')
        with deadlines.use(effective_budget(row)):
            checkpoint('release-start')
            for field in ['key','conf','ca']:
                st=Path(config['writer'][field]).lstat()
                if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_mode & 0o022:raise Rejected('target_permissions')
            with open(root/'writer.lock','a+b') as lock:
                fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
                with contextlib.closing(open_main(writer,config.get('sqlite_max_pages'))) as main,readonly(root/'recovery.db') as catalog:
                    stage='storage_validation';check_source(main,writer,catalog,row)
                    filesystem_probe(root,row['probe'],checkpoint)
                    def sqlite_probe():
                        main.execute('BEGIN IMMEDIATE')
                        try:main.execute('UPDATE storage_probe SET value=? WHERE id=1',(os.urandom(64),));deadlines.check();main.commit();deadlines.check()
                        except Exception:main.rollback();raise
                    sqlite_probe();storage_done=True;checkpoint('release-storage-verified');check_source(main,writer,catalog,row)
                    core=writer.read(main);name=core['committed'];stage='certificate_validation';fingerprint=writer.check(name)
                    if os.readlink(root/'active.conf')!='v-'+name+'/tls.conf':raise Rejected('committed_pointer_required')
                    stage='tls_confirmation';observed=writer.confirm(name,time.monotonic()+5)
                    if observed!=fingerprint or writer.check(name)!=fingerprint:raise Rejected('wire_certificate')
                    tls_done=True;checkpoint('release-confirmed');check_source(main,writer,catalog,row)
                    stage='receipt_publication';record=expected_receipt(row,fingerprint,name)
                    with decision(root/'journal.db'):
                        main.execute('BEGIN IMMEDIATE')
                        try:
                            check_source(main,writer,catalog,row);receipt(main)
                            main.execute('CREATE TABLE IF NOT EXISTS release_preparation(id INTEGER PRIMARY KEY CHECK(id=1),record TEXT NOT NULL)')
                            main.execute('INSERT OR REPLACE INTO release_preparation VALUES(1,?)',(json.dumps(record),))
                            checkpoint('release-main-commit');check_source(main,writer,catalog,row);deadlines.check();main.commit();written=True
                        except Exception:main.rollback();raise
                    checkpoint('release-main-committed');stage='result_publication'
                    def final_check():
                        checkpoint('release-result-commit');check_source(main,writer,catalog,row)
                        if receipt(main)!=record:raise Rejected('stale_release_receipt')
                        # Detect faults introduced after the first probes/receipt.
                        filesystem_probe(root,row['probe'],checkpoint);sqlite_probe();check_source(main,writer,catalog,row)
                        if writer.check(name)!=fingerprint:raise Rejected('certificate_drift')
                    store.commit_checkpoint=final_check
                    return store.finish(identity,'RELEASE_VERIFIED_CLOSED',{'storage_verified':True,'certificate_verified':True,'tls_confirmed':True,'committed':name,'fingerprint':fingerprint,'receipt_digest':digest(record),'updates_enabled':False,'release_authorized':False})
    except Exception as error:
        try:effective_budget(row)
        except deadlines.Expired:error=deadlines.Expired('release_or_source_expired')
        return store.finish(identity,'EXPIRED' if isinstance(error,deadlines.Expired) else 'FAILED',{'storage_verified':False,'certificate_verified':False,'tls_confirmed':False,'observed_storage_verified':storage_done,'observed_tls_confirmed':tls_done,'receipt_commit_observed':written,'receipt_commit_may_have_happened':stage in {'receipt_publication','result_publication'},'failure_stage':stage,'error':type(error).__name__,'reason':str(error) if isinstance(error,(Rejected,deadlines.Expired)) else None,'sqlite_error':getattr(error,'sqlite_errorname',None),'errno':getattr(error,'errno',None),'updates_enabled':False,'release_authorized':False})
