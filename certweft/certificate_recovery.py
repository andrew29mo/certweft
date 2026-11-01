"""Root committed-certificate restoration, never opening normal admission."""
import contextlib,fcntl,os,stat,time
from pathlib import Path
from . import deadlines
from .core import Rejected
from .executor import FixedWriter
from .recovery import RecoveryStore,require_authority,open_main,validate_journal,filesystem_probe

def recover_certificate(config,identity,checkpoint=lambda point:None):
    store=RecoveryStore(Path(config['writer']['root']));row=store.get(identity);selected=False;confirmed=False
    store.commit_checkpoint=lambda:checkpoint('certificate-proof-commit')
    writer=FixedWriter(**config['writer']);writer.master=config['master']
    try:
        row=store.begin(identity)
        if row['kind']!='recover-certificate':raise Rejected('operation_kind')
        with deadlines.use(row['timing']['budget']):
            checkpoint('restoration-start');deadlines.check();require_authority(writer.root,row)
            for field in ['key','conf','ca']:
                st=Path(config['writer'][field]).lstat()
                if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_mode & 0o022:raise Rejected('target_permissions')
            with open(writer.root/'writer.lock','a+b') as lock:
                fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
                with contextlib.closing(open_main(writer,config.get('sqlite_max_pages'))) as db:
                    health=validate_journal(db,writer,row['target'])
                    filesystem_probe(writer.root,row['probe'],checkpoint)
                    db.execute('BEGIN IMMEDIATE');db.execute('UPDATE storage_probe SET value=? WHERE id=1',(os.urandom(64),));deadlines.check();db.commit();deadlines.check()
                    validate_journal(db,writer,row['target'])
                    name=row['target']['committed'];fingerprint=writer.check(name)
                    checkpoint('restore-validated');deadlines.check();require_authority(writer.root,row)
                    selected=True;writer.select(name);checkpoint('restore-selected');deadlines.check()
                    writer.reload();checkpoint('restore-reloaded');deadlines.check()
                    observed=writer.confirm(name,time.monotonic()+5)
                    if observed!=fingerprint:raise Rejected('wire_certificate')
                    confirmed=True;checkpoint('restore-confirmed');deadlines.check()
                    if writer.check(name)!=fingerprint:raise Rejected('target_drift')
                    validate_journal(db,writer,row['target']);require_authority(writer.root,row)
                    proof={'storage_verified':True,'certificate_verified':True,'tls_confirmed':True,'restored':True,'updates_enabled':False,'committed':name,'fingerprint':fingerprint,'prior_health':health}
                    store.finish(identity,'CERTIFICATE_VERIFIED',proof)
                    checkpoint('certificate-proof');deadlines.check()
                    return store.complete_closed(identity,proof,checkpoint)
    except Exception as error:
        try:deadlines.remaining(row['timing']['budget'])
        except deadlines.Expired:error=deadlines.Expired('recovery_expired')
        state='EXPIRED' if isinstance(error,deadlines.Expired) else 'FAILED'
        return store.finish(identity,state,{'restored':False,'updates_enabled':False,'may_have_changed_service':selected,'tls_observed_before_failure':confirmed,'error':type(error).__name__,'reason':str(error) if isinstance(error,(Rejected,deadlines.Expired)) else None,'sqlite_error':getattr(error,'sqlite_errorname',None),'errno':getattr(error,'errno',None)})
