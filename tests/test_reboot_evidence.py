"""Challenge the exact read-only boot observer used in the VM, not a replica."""
import contextlib,io,json,pathlib,sqlite3,tempfile,unittest
from unittest.mock import patch
from tools.reboot_vm import OBSERVER

class BootObserver(unittest.TestCase):
    def fixture(self,folder):
        base=pathlib.Path(folder);root=base/'state';root.mkdir();lab=base/'lab';lab.mkdir()
        for name,sql in [('journal.db',"CREATE TABLE state(id,data); INSERT INTO state VALUES(1,'{\"state\":\"APPLYING\"}'); CREATE TABLE requests(id,state,result); INSERT INTO requests VALUES('old','RUNNING',NULL);"),('recovery.db',"CREATE TABLE recovery_requests(id,state,result);")]:
            with contextlib.closing(sqlite3.connect(root/name)) as db, db:db.executescript(sql)
        (root/'execution.json').write_text('{}');(root/'active.conf').symlink_to('v-test/tls.conf')
        (base/'boot').write_text('new');(base/'uptime').write_text('2.5 0')
        code=OBSERVER.replace('/var/lib/certweft-reboot-lab',str(lab)).replace('/var/lib/certweft',str(root)).replace('/proc/sys/kernel/random/boot_id',str(base/'boot')).replace('/proc/uptime',str(base/'uptime'))
        # First execution obtains the actual observer's proposed snapshot but
        # must refuse a mismatching plan without publishing it.
        (lab/'plan.json').write_text(json.dumps({'boot_id':'old','case':'pending','before':{}}))
        scope={}
        with patch('os.popen',return_value=io.StringIO('0')):
            with self.assertRaises(KeyError):exec(code,scope)
        before=scope['value'];(lab/'plan.json').write_text(json.dumps({'boot_id':'old','case':'pending','before':before}))
        return root,lab,code
    def test_pending_catalog_is_compared_read_only_and_published_once(self):
        with tempfile.TemporaryDirectory() as folder:
            root,lab,code=self.fixture(folder);original={p.name:p.read_bytes() for p in root.iterdir() if p.is_file()}
            with patch('os.popen',return_value=io.StringIO('0')):exec(code,{})
            value=json.loads((lab/'observed-pending.json').read_text());self.assertEqual(value['state']['state'],'APPLYING');self.assertEqual(value['requests'][0][1],'RUNNING')
            self.assertEqual(original,{p.name:p.read_bytes() for p in root.iterdir() if p.is_file()})
            with patch('os.popen',return_value=io.StringIO('0')):
                with self.assertRaises(FileExistsError):exec(code,{})
    def test_shutdown_changes_are_not_accepted_as_reboot_evidence(self):
        with tempfile.TemporaryDirectory() as folder:
            root,lab,code=self.fixture(folder)
            with contextlib.closing(sqlite3.connect(root/'journal.db')) as db, db:db.execute("UPDATE state SET data='{\"state\":\"READY\"}'")
            with patch('os.popen',return_value=io.StringIO('0')):
                with self.assertRaisesRegex(AssertionError,'changed_before_writer'):exec(code,{})
            self.assertFalse((lab/'observed-pending.json').exists())
    def test_already_started_writer_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            _,lab,code=self.fixture(folder)
            with patch('os.popen',return_value=io.StringIO('42')):
                with self.assertRaisesRegex(AssertionError,'writer_started_before_observation'):exec(code,{})
            self.assertFalse((lab/'observed-pending.json').exists())

class RebootControls(unittest.TestCase):
    def test_observation_must_be_from_current_boot(self):
        from tools.reboot_vm import boot_pair
        before={k:None for k in ['journal_sha256','recovery_sha256','gate_sha256','state','requests','recovery','active']}
        plan={'boot_id':'old','before':before};obs={**before,'boot_id':'new','writer_main_pid':'0'}
        boot_pair(plan,obs,'new')
        with self.assertRaisesRegex(AssertionError,'observer_not_current_boot'):boot_pair(plan,obs,'another')
        with self.assertRaisesRegex(AssertionError,'same_boot'):boot_pair({**plan,'boot_id':'new'},obs,'new')
    def test_blanket_executor_failure_cannot_pass_stale_control(self):
        from tools.reboot_vm import activation_control
        stale={'state':'FAILED','result':{'error':'Rejected','expired':False}}
        with self.assertRaisesRegex(AssertionError,'fresh_authority_cannot_activate'):
            activation_control(stale,{'result':{'state':'FAILED'}},'old','old','target')
        with self.assertRaisesRegex(AssertionError,'fresh_activation_not_observed'):
            activation_control(stale,{'result':{'state':'COMMITTED'}},'old','old','target')
        activation_control(stale,{'result':{'state':'COMMITTED'}},'old','target','target')

class SnapshotLifetime(unittest.TestCase):
    @unittest.skipUnless(pathlib.Path('/proc/self/fd').exists(),'Linux descriptor inventory')
    def test_snapshot_closes_both_database_descriptors_without_gc(self):
        import gc,os
        from tools import reboot_vm
        with tempfile.TemporaryDirectory() as folder:
            root,_,_=BootObserver().fixture(folder);enabled=gc.isenabled();gc.disable()
            try:
                with patch.object(reboot_vm,'STATE',root):reboot_vm.snapshot()
                targets=[]
                for fd in pathlib.Path('/proc/self/fd').iterdir():
                    try:targets.append(os.readlink(fd))
                    except FileNotFoundError:pass
                self.assertFalse(any(str(root/'journal.db')==p or str(root/'recovery.db')==p for p in targets),targets)
            finally:
                if enabled:gc.enable()

class StorageRecoveryControls(unittest.TestCase):
    def test_old_failed_root_prefix_is_read_when_gate_is_closed(self):
        from certweft.cli import recover
        from certweft.core import Rejected
        seen=[]
        def call(endpoint,body):
            seen.append(body)
            if body['op']=='recovery-status':return {'gate':{'state':'VERIFY_REQUIRED'},'executor_busy':False}
            self.assertEqual(body['op'],'recovery-request-status')
            return {'result':{'request_id':'old-cert','kind':'recover-certificate','state':'FAILED'}}
        with patch('certweft.cli.os.geteuid',return_value=0),patch('certweft.cli.call',side_effect=call):
            with self.assertRaisesRegex(Rejected,'recovery_step_FAILED'):recover('unused','old',10)
        self.assertTrue(any(v['op']=='recovery-request-status' and v['request_id']=='old-cert' for v in seen))
        self.assertTrue(all(v['op'] in {'recovery-status','recovery-request-status'} for v in seen))
    def test_repair_cannot_rewrite_old_terminal_or_request_authority(self):
        import copy
        from tools.storage_reboot_vm import preserve_history
        before={'normal':[{'id':'old','state':'COMMITTED','result':'old-result','digest':'d','timing':'old-budget'},{'id':'pending','state':'RUNNING','result':None,'digest':'p','timing':'pending-budget'}],'root':[{'id':'root-old','state':'FAILED','result':'failure','timing':'old-root-budget','target':'old-target'}]}
        after=copy.deepcopy(before);after['normal'][1].update(state='INTERRUPTED',result='reconciled');preserve_history(before,after)
        for group,key,value,message in [('normal','result','rewritten','terminal_history_rewritten'),('root','result','rewritten','terminal_history_rewritten'),('normal','timing','extended','history_identity_or_timing_changed')]:
            bad=copy.deepcopy(after);bad[group][0][key]=value
            with self.assertRaisesRegex(AssertionError,message):preserve_history(before,bad)

class StorageFailureProvenance(unittest.TestCase):
    def test_unrelated_or_old_startup_failure_cannot_count_as_storage_fault(self):
        from tools.storage_reboot_vm import failure_cause
        p={'InvocationID':'inv','ExecMainStatus':'1','NRestarts':'3'}
        row={'_BOOT_ID':'newboot','_SYSTEMD_INVOCATION_ID':'inv','_SYSTEMD_UNIT':'certweft.service','MESSAGE':'File /opt/certweft/lib/python3.12/site-packages/certweft/gate.py\nOSError: [Errno 28] No space left on device'}
        failure_cause('enospc',p,[row],'new-boot')
        for other in [{**row,'_BOOT_ID':'oldboot'},{**row,'_SYSTEMD_INVOCATION_ID':'old'},{**row,'MESSAGE':'ModuleNotFoundError: certweft'}]:
            with self.assertRaisesRegex(AssertionError,'expected_writer_storage_errno_not_observed'):failure_cause('enospc',p,[other],'new-boot')
        with self.assertRaisesRegex(AssertionError,'expected_writer_storage_stage_not_observed'):
            failure_cause('enospc',p,[{**row,'MESSAGE':'OSError: [Errno 28] unrelated file'}],'new-boot')
