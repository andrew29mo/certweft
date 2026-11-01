import json,os,sqlite3,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from certweft.core import Rejected
from certweft.gate import Gate
from certweft.operations import Operations

class RestartGate(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.gate=Gate(self.root)
    def tearDown(self):self.temp.cleanup()
    def test_preexisting_running_record_blocks_unclean_restart(self):
        self.gate.provision();first=self.gate.start();self.gate.require(Gate.token(first))
        second=Gate(self.root).start();self.assertEqual(second['state'],'RECOVERY_REQUIRED')
        self.assertNotEqual(second['epoch'],first['epoch'])
        with self.assertRaises(Rejected):self.gate.require(Gate.token(first))
        with self.assertRaisesRegex(Rejected,'recovery_required'):self.gate.require(Gate.token(second))
    def test_clean_stop_allows_fresh_session_but_rejects_old_authority(self):
        self.gate.provision();old=self.gate.start();self.gate.stop(Gate.token(old));new=self.gate.start()
        self.assertEqual(new['state'],'RUNNING')
        with self.assertRaisesRegex(Rejected,'stale_gate_authority'):self.gate.require(Gate.token(old))
    def test_missing_legacy_gate_never_enrolls_healthy(self):
        self.assertEqual(self.gate.start()['state'],'RECOVERY_REQUIRED')
    def test_prepare_is_cas_and_never_releases_gate(self):
        initial=self.gate.start();prepared=self.gate.prepare(Gate.token(initial))
        self.assertEqual(prepared['state'],'VERIFY_REQUIRED');self.assertEqual(prepared['revision'],initial['revision']+1)
        with self.assertRaisesRegex(Rejected,'stale_gate_authority'):self.gate.prepare(Gate.token(initial))
        with self.assertRaises(Rejected):self.gate.require(Gate.token(prepared))
        restarted=self.gate.start()
        with self.assertRaisesRegex(Rejected,'stale_gate_authority'):self.gate.prepare(Gate.token(prepared))
        self.assertEqual(restarted['state'],'RECOVERY_REQUIRED')
    def test_prepare_cannot_modify_running_session(self):
        self.gate.provision();current=self.gate.start()
        with self.assertRaisesRegex(Rejected,'not_recovery_required'):self.gate.prepare(Gate.token(current))
        self.assertEqual(self.gate.read(),current)
    def test_corrupt_record_is_rejected_not_replaced(self):
        self.gate.path.write_text('{broken');os.chmod(self.gate.path,0o600)
        with self.assertRaisesRegex(Rejected,'gate_schema'):self.gate.start()
        self.assertEqual(self.gate.path.read_text(),'{broken')
    def test_symlink_and_public_record_rejected(self):
        target=self.root/'other';target.write_text('untouched');self.gate.path.symlink_to(target)
        with self.assertRaises(OSError):self.gate.start()
        self.assertEqual(target.read_text(),'untouched');self.gate.path.unlink();self.gate.provision();os.chmod(self.gate.path,0o644)
        with self.assertRaisesRegex(Rejected,'gate_permissions'):self.gate.start()
    def test_fsync_failure_is_not_successful_start(self):
        self.gate.provision();old=self.gate.read()
        with patch('certweft.gate.os.fsync',side_effect=OSError('fsync fixture')):
            with self.assertRaises(OSError):self.gate.start()
        self.assertEqual(self.gate.read(),old);self.assertEqual(list(self.root.glob('*.pending')),[])
    def test_formal_commit_gate_rejects_stale_session_before_sql_write(self):
        self.gate.provision();initial=self.gate.start();ops=Operations(self.root);ops.initialize()
        body={'op':'submit','request_id':'one','certificate':'pem','epoch':'core','revision':0}
        ops.admit(body);ops.begin('one');self.gate.start()
        with sqlite3.connect(ops.path) as db:
            db.execute('CREATE TABLE state(id INTEGER PRIMARY KEY,data TEXT)');db.commit()
            with self.assertRaises(Rejected):Operations.commit(db,'one',{'committed':'new'},gate_authority=Gate.token(initial))
            self.assertIsNone(db.execute('SELECT * FROM state').fetchone())
        self.assertEqual(ops.get('one')['state'],'RUNNING')

    def test_gate_change_after_sql_writes_prevents_final_commit(self):
        self.gate.provision();current=self.gate.start();ops=Operations(self.root);ops.initialize()
        from certweft.recovery import RecoveryStore
        RecoveryStore(self.root).initialize()
        ops.admit({'op':'submit','request_id':'late','certificate':'pem','epoch':'core','revision':0});ops.begin('late')
        with sqlite3.connect(ops.path) as db:
            db.execute('CREATE TABLE state(id INTEGER PRIMARY KEY,data TEXT)');db.execute('INSERT INTO state VALUES(1,?)',(json.dumps({'committed':'old'}),));db.commit()
            with self.assertRaises(Rejected):Operations.commit(db,'late',{'committed':'new'},checkpoint=self.gate.start,gate_authority=Gate.token(current))
            db.rollback();self.assertEqual(json.loads(db.execute('SELECT data FROM state').fetchone()[0]),{'committed':'old'})
        self.assertEqual(ops.get('late')['state'],'RUNNING')

    def test_stop_directory_fsync_failure_does_not_authorize_restart(self):
        import errno
        self.gate.provision();current=self.gate.start();real_fsync=os.fsync;calls=[]
        def fail_second(fd):
            calls.append(fd)
            if len(calls)==2:raise OSError(errno.EIO,'injected directory sync')
            return real_fsync(fd)
        with patch('certweft.gate.os.fsync',side_effect=fail_second):
            with self.assertRaises(OSError):self.gate.stop(Gate.token(current))
        self.assertEqual(self.gate.read()['state'],'STOPPED')
        self.assertFalse(self.gate.certified(self.gate.read()))
        self.assertEqual(self.gate.start()['state'],'RECOVERY_REQUIRED')
    def test_stopped_record_without_matching_receipt_never_opens(self):
        self.gate.provision();original=self.gate.read();self.gate.receipt.unlink()
        self.assertEqual(self.gate.start()['state'],'RECOVERY_REQUIRED')
        self.gate.write(original);self.gate.receipt.write_text('{}');os.chmod(self.gate.receipt,0o600)
        self.assertEqual(self.gate.start()['state'],'RECOVERY_REQUIRED')
    def test_stop_receipt_is_bound_to_exact_state_and_private_file(self):
        self.gate.provision();current=self.gate.start();stopped=self.gate.stop(Gate.token(current))
        self.assertTrue(self.gate.certified(stopped))
        self.assertFalse(self.gate.certified({**stopped,'reason':'new_store'}))
        os.chmod(self.gate.receipt,0o644)
        with self.assertRaisesRegex(Rejected,'receipt_permissions'):self.gate.start()
