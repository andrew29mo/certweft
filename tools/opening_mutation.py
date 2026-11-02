"""One bounded real-service negative control; never edits the working source."""
import hashlib,json,os,pathlib,shutil,subprocess,sys,tempfile
from tools.executor_vm import P,hashes

def check_readiness_mutation():
    if os.geteuid()!=0:raise PermissionError('isolated Linux VM root required')
    original=hashes();directory=pathlib.Path(tempfile.mkdtemp(prefix='cw-opening-mutation-',dir='/var/tmp'))
    outcome={};clean=False
    try:
        for name in ['certweft','tools','tests','policy']:
            shutil.copytree(P/name,directory/name,ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
        shutil.copyfile(P/'pyproject.toml',directory/'pyproject.toml')
        changed=directory/'certweft/opening.py';text=changed.read_text()
        needle="            deadlines.remaining(row['timing']['budget'])\n            return True\n"
        if text.count(needle)!=1:raise AssertionError('mutation_target_not_unique')
        changed.write_text(text.replace(needle,'            return True\n',1))
        copied={str(p.relative_to(directory)):hashlib.sha256(p.read_bytes()).hexdigest() for p in [directory/'pyproject.toml',*(f for name in ['certweft','tools','tests','policy'] for f in (directory/name).rglob('*') if f.is_file() and '__pycache__' not in f.parts and f.suffix!='.pyc')]}
        different=[name for name in original if copied.get(name)!=original[name]]
        if different!=['certweft/opening.py'] or set(copied)!=set(original):raise AssertionError('mutation_changed_other_source')
        script="""import json,os
os.umask(0o077)
from tools.storage_vm import scenario
try:
 scenario('sqlite_full','post',check_gate=True,certificate_mode='opening-readiness-expiry')
except AssertionError as error:
 if str(error)!='expired_readiness_response':raise
 print(json.dumps({'expected_failure':'expired_readiness_response','formal_service_case_rejected':True}))
else:raise AssertionError('known_readiness_bug_survived_test')
"""
        result=subprocess.run([sys.executable,'-c',script],cwd=directory,capture_output=True,timeout=90)
        if result.returncode!=0:raise AssertionError('mutation_control_failed_'+str(result.returncode))
        observed=json.loads(result.stdout)
        if observed!={'expected_failure':'expired_readiness_response','formal_service_case_rejected':True}:raise AssertionError('mutation_control_bad_result')
        outcome={'passed':True,'mutation':'remove_final_readiness_deadline_check','expected_failure':observed['expected_failure'],'formal_service_case_rejected':True,'only_opening_source_changed':True,'original_opening_sha256':original['certweft/opening.py'],'mutant_opening_sha256':copied['certweft/opening.py'],'working_source_unchanged':hashes()==original}
        if not outcome['working_source_unchanged']:raise AssertionError('working_source_changed')
    finally:
        shutil.rmtree(directory);clean=not directory.exists()
    # The expected fixture assertion propagates only after its owned service,
    # executor, Nginx, mount and loop cleanup succeeds. Other failures are rejected.
    return {**outcome,'cleanup_verified':clean}
