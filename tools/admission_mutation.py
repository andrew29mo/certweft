"""Bounded SQL negative controls in disposable source copies; not TLS proof."""
import hashlib,json,os,pathlib,shutil,subprocess,sys,tempfile
from tools.executor_vm import P,hashes

def check_commit_mutations():
    if os.geteuid()!=0:raise PermissionError('isolated Linux VM root required')
    original=hashes();outcomes=[]
    needle="            if gate_authority is not None:require_updates(Path(path).parent,gate_authority,db)\n"
    for index,method,message in [(0,'test_main_only_receipt_cannot_admit_or_commit','commit_checkpoint_reached_before_admission'),(1,'test_commit_second_guard_rejects_gate_change_after_sql_writes','Rejected not raised')]:
        directory=pathlib.Path(tempfile.mkdtemp(prefix='cw-admission-mutation-',dir='/var/tmp'));outcome={}
        try:
            for name in ['certweft','tools','tests','policy']:shutil.copytree(P/name,directory/name,ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
            changed=directory/'certweft/operations.py';text=changed.read_text()
            if text.count(needle)!=2:raise AssertionError('mutation_target_not_unique')
            start=text.find(needle) if index==0 else text.rfind(needle)
            changed.write_text(text[:start]+text[start:].replace(needle,'            # Deliberately removed guard for negative control.\n',1))
            copied={str(p.relative_to(directory)):hashlib.sha256(p.read_bytes()).hexdigest() for name in ['certweft','tools','tests','policy'] for p in (directory/name).glob('*') if p.is_file()}
            if set(copied)!=set(original) or [k for k in original if copied[k]!=original[k]]!=['certweft/operations.py']:raise AssertionError('mutation_changed_other_source')
            script="""import io,json,os,sys,unittest
os.umask(0o077);sys.path.insert(0,'tests')
method,expected=sys.argv[1:]
s=unittest.defaultTestLoader.loadTestsFromName('test_admission.AdmissionLedger.'+method)
r=unittest.TextTestRunner(stream=io.StringIO()).run(s)
assert r.testsRun==1 and len(r.failures)==1 and not r.errors and not r.skipped
assert expected in r.failures[0][1],r.failures[0][1]
print(json.dumps({'expected_test_failure':method,'assertion_observed':expected}))
"""
            r=subprocess.run([sys.executable,'-c',script,method,message],cwd=directory,capture_output=True,timeout=30)
            if r.returncode!=0:raise AssertionError('commit_mutation_control_failed_'+str(index))
            observed=json.loads(r.stdout)
            if observed!={'expected_test_failure':method,'assertion_observed':message}:raise AssertionError('mutation_result')
            outcome={'passed':True,'removed_guard':index+1,**observed,'original_operations_sha256':original['certweft/operations.py'],'mutant_operations_sha256':copied['certweft/operations.py'],'only_operations_source_changed':True}
        finally:shutil.rmtree(directory)
        outcomes.append({**outcome,'cleanup_verified':not directory.exists()})
    if hashes()!=original:raise AssertionError('working_source_changed')
    return {'passed':True,'scope':'real SQLite unit contracts with crypto mocks; not formal-service TLS qualification','controls':outcomes,'working_source_unchanged':True,'cleanup_verified':all(x['cleanup_verified'] for x in outcomes)}

def check_inventory_mutation():
    """Prove the formal service test detects omitted pre-communicate cleanup."""
    original=hashes();directory=pathlib.Path(tempfile.mkdtemp(prefix='cw-admission-mutation-',dir='/var/tmp'));outcome={}
    try:
        for name in ['certweft','tools','tests','policy']:shutil.copytree(P/name,directory/name,ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
        changed=directory/'certweft/service.py';text=changed.read_text()
        needle='            finally:\n                if child is not None:\n                    with process_lock:\n'
        if text.count(needle)!=1:raise AssertionError('inventory_mutation_target')
        changed.write_text(text.replace(needle,'            finally:\n                if child is not None and child.stdin.closed:\n                    with process_lock:\n',1))
        copied={str(p.relative_to(directory)):hashlib.sha256(p.read_bytes()).hexdigest() for name in ['certweft','tools','tests','policy'] for p in (directory/name).glob('*') if p.is_file()}
        if set(copied)!=set(original) or [k for k in original if copied[k]!=original[k]]!=['certweft/service.py']:raise AssertionError('inventory_mutation_changed_other_source')
        script="""import json,os
os.umask(0o077)
from tools.storage_vm import scenario
try:scenario('sqlite_full','post',check_gate=True,certificate_mode='admission-inventory-failure')
except AssertionError as error:
 if str(error)!='inventory_failure_leaked_lease_holder':raise
 print(json.dumps({'expected_failure':str(error),'formal_service_case_rejected':True}))
else:raise AssertionError('inventory_leak_survived_test')
"""
        r=subprocess.run([sys.executable,'-c',script],cwd=directory,capture_output=True,timeout=90)
        if r.returncode!=0:raise AssertionError('inventory_mutation_control_failed_'+str(r.returncode))
        observed=json.loads(r.stdout)
        if observed!={'expected_failure':'inventory_failure_leaked_lease_holder','formal_service_case_rejected':True}:raise AssertionError('inventory_mutation_result')
        outcome={'passed':True,'scope':'formal root service with real /dev/full inventory write ENOSPC','only_service_source_changed':True,'original_service_sha256':original['certweft/service.py'],'mutant_service_sha256':copied['certweft/service.py'],**observed}
    finally:shutil.rmtree(directory)
    if hashes()!=original:raise AssertionError('working_source_changed')
    return {**outcome,'cleanup_verified':not directory.exists(),'working_source_unchanged':True}

def check_group_reap_mutation():
    """The real-process unit must detect skipping a dead leader's live group."""
    original=hashes();directory=pathlib.Path(tempfile.mkdtemp(prefix='cw-admission-mutation-',dir='/var/tmp'));outcome={}
    try:
        for name in ['certweft','tools','tests','policy']:shutil.copytree(P/name,directory/name,ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
        changed=directory/'certweft/service.py';text=changed.read_text();needle='    if terminate:\n'
        if text.count(needle)!=1:raise AssertionError('group_mutation_target')
        changed.write_text(text.replace(needle,'    if terminate and child.poll() is None:\n',1))
        copied={str(p.relative_to(directory)):hashlib.sha256(p.read_bytes()).hexdigest() for name in ['certweft','tools','tests','policy'] for p in (directory/name).glob('*') if p.is_file()}
        if set(copied)!=set(original) or [k for k in original if copied[k]!=original[k]]!=['certweft/service.py']:raise AssertionError('group_mutation_changed_other_source')
        script="""import io,json,sys,unittest
sys.path.insert(0,'tests')
s=unittest.defaultTestLoader.loadTestsFromName('test_service_process.ExecutorGroup.test_exited_leader_does_not_skip_pipe_and_lease_holding_descendant')
r=unittest.TextTestRunner(stream=io.StringIO()).run(s)
assert r.testsRun==1 and len(r.failures)==1 and not r.errors and not r.skipped
assert 'descendant_survived_group_reap' in r.failures[0][1],r.failures[0][1]
print(json.dumps({'expected_failure':'descendant_survived_group_reap','real_process_unit_rejected':True}))
"""
        r=subprocess.run([sys.executable,'-c',script],cwd=directory,capture_output=True,timeout=30)
        if r.returncode!=0:raise AssertionError('group_mutation_control_failed_'+str(r.returncode))
        observed=json.loads(r.stdout)
        if observed!={'expected_failure':'descendant_survived_group_reap','real_process_unit_rejected':True}:raise AssertionError('group_mutation_result')
        outcome={'passed':True,'scope':'real-process unit with inherited pipes and flock; not an installed service timeout scenario','only_service_source_changed':True,'original_service_sha256':original['certweft/service.py'],'mutant_service_sha256':copied['certweft/service.py'],**observed}
    finally:shutil.rmtree(directory)
    if hashes()!=original:raise AssertionError('working_source_changed')
    return {**outcome,'cleanup_verified':not directory.exists(),'working_source_unchanged':True}
