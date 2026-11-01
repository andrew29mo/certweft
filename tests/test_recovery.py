import hashlib,json,os,sqlite3,tempfile,unittest,uuid
from pathlib import Path
from unittest.mock import patch
from certweft.core import Writer,Rejected
from certweft.gate import Gate
from certweft.operations import Operations
from certweft.recovery import RecoveryStore,verify
from certweft import deadlines

class DurableVerification(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.ops=Operations(self.root);self.ops.initialize();os.chmod(self.root/'journal.db',0o600)
        self.writer=Writer(self.root,'unused','unused','unused','unused','localhost','127.0.0.1',1)
        name=uuid.uuid4().hex;directory=self.root/('v-'+name);directory.mkdir()
        for file in ['cert.pem','key.pem','tls.conf']:(directory/file).write_text('storage fixture, not a real certificate')
        (self.root/'active.conf').symlink_to('v-'+name+'/tls.conf')
        self.state=dict(schema=1,state='READY',epoch=uuid.uuid4().hex,revision=0,committed=name,committed_digest=self.writer.digest(name),candidate=None)
        with sqlite3.connect(self.root/'journal.db') as db:db.execute('CREATE TABLE state(id INTEGER PRIMARY KEY,data TEXT)');db.execute('INSERT INTO state VALUES(1,?)',(json.dumps(self.state),))
        self.gate=Gate(self.root);self.gate.provision();self.gate.start();self.gate.start();gate=self.gate.prepare(Gate.token(self.gate.read()))
        self.store=RecoveryStore(self.root);self.store.initialize();self.body={'op':'verify-storage','request_id':'check','timeout_seconds':10,**Gate.token(gate)}
        self.config={'writer':{'root':str(self.root),'nginx':'unused','conf':'unused','ca':'unused','key':'unused','host':'localhost','ip':'127.0.0.1','port':1}}
    def tearDown(self):self.temp.cleanup()
    def test_real_validation_replay_does_not_probe_twice_or_unlock(self):
        row,created=self.store.admit(self.body,self.writer);self.assertTrue(created)
        result=verify(self.config,'check');self.assertEqual(result['state'],'STORAGE_VERIFIED')
        with sqlite3.connect(self.root/'journal.db') as db:probe=db.execute('SELECT value FROM storage_probe').fetchone()[0]
        same,created=self.store.admit(self.body,self.writer);self.assertFalse(created);self.assertEqual(same,result)
        with sqlite3.connect(self.root/'journal.db') as db:self.assertEqual(db.execute('SELECT value FROM storage_probe').fetchone()[0],probe)
        self.assertEqual(self.gate.read()['state'],'VERIFY_REQUIRED');self.assertFalse(result['result']['updates_enabled']);self.assertFalse(result['result']['restored'])
        self.assertEqual(list(self.root.glob('verify-*')),[])
        with self.assertRaisesRegex(Rejected,'request_conflict'):self.store.admit({**self.body,'timeout_seconds':9},self.writer)
    def test_restart_interrupts_without_resetting_original_budget(self):
        original=self.store.admit(self.body,self.writer)[0];self.store.begin('check');self.gate.start()
        reopened=RecoveryStore(self.root);reopened.initialize();self.assertTrue(reopened.reconcile())
        result=reopened.get('check');self.assertEqual(result['state'],'INTERRUPTED');self.assertEqual(result['timing'],original['timing'])
        self.assertFalse(reopened.admit(self.body,self.writer)[1])
        with self.assertRaisesRegex(Rejected,'stale_gate_authority'):reopened.admit({**self.body,'request_id':'new'},self.writer)
    def test_expired_request_never_runs_probe(self):
        row=self.store.admit(self.body,self.writer)[0];budget=row['timing']['budget']
        with patch('certweft.deadlines.now_ns',return_value=budget['expires_boot_ns']+1),patch('certweft.deadlines.time.time_ns',return_value=budget['accepted_wall_ns']+budget['seconds']*1_000_000_000+1):
            with patch('certweft.recovery.filesystem_probe',side_effect=AssertionError('must not probe')):
                self.assertEqual(verify(self.config,'check')['state'],'EXPIRED')
        self.assertEqual(self.store.get('check')['timing'],row['timing'])
    def test_pager_full_is_real_and_does_not_clear_health_or_gate(self):
        self.store.admit(self.body,self.writer)
        with sqlite3.connect(self.root/'journal.db') as db:
            db.execute('CREATE TABLE pressure(data BLOB)');db.execute('CREATE TRIGGER full_probe BEFORE UPDATE ON storage_probe BEGIN INSERT INTO pressure VALUES(zeroblob(65536)); END')
            maximum=db.execute('PRAGMA page_count').fetchone()[0]+1
        result=verify({**self.config,'sqlite_max_pages':maximum},'check')
        self.assertEqual(result['state'],'FAILED');self.assertEqual(result['result']['sqlite_error'],'SQLITE_FULL')
        with sqlite3.connect(self.root/'journal.db') as db:self.assertEqual(json.loads(db.execute('SELECT data FROM state').fetchone()[0]),self.state)
        self.assertEqual(self.gate.read()['state'],'VERIFY_REQUIRED')
    def test_unknown_probe_directory_is_not_deleted(self):
        row=self.store.admit(self.body,self.writer)[0];directory=self.root/('verify-'+row['probe']);directory.mkdir();(directory/'unknown').write_text('preserve')
        self.assertEqual(verify(self.config,'check')['state'],'FAILED');self.assertEqual((directory/'unknown').read_text(),'preserve')
    def test_target_drift_and_missing_schema_never_verify(self):
        self.store.admit(self.body,self.writer)
        with sqlite3.connect(self.root/'journal.db') as db:db.execute('DROP TABLE storage_probe')
        result=verify(self.config,'check');self.assertEqual(result['state'],'FAILED');self.assertEqual(result['result']['reason'],'journal_schema')
        self.assertEqual(list(self.root.glob('verify-*')),[])
    def test_history_has_independent_bounded_capacity(self):
        for i in range(64):
            job={'op':'submit','request_id':'normal-'+str(i),'certificate':'pem','epoch':'stale','revision':0}
            self.ops.admit(job);self.ops.begin(job['request_id']);self.ops.finish(job['request_id'],'FAILED',{})
        for i in range(16):
            body={**self.body,'request_id':'recovery-'+str(i)};self.assertTrue(self.store.admit(body,self.writer)[1]);self.store.finish(body['request_id'],'FAILED',{'test_fixture':True})
        self.assertFalse(self.store.admit({**self.body,'request_id':'recovery-0'},self.writer)[1])
        with self.assertRaisesRegex(Rejected,'recovery_history_full'):self.store.admit(self.body,self.writer)
        self.assertEqual(self.gate.read()['state'],'VERIFY_REQUIRED')

    def test_status_does_not_recreate_missing_journal_schema(self):
        with sqlite3.connect(self.root/'journal.db') as db:db.execute('DROP TABLE state')
        with self.assertRaises(sqlite3.OperationalError):self.writer.status()
        with sqlite3.connect(self.root/'journal.db') as db:self.assertIsNone(db.execute("SELECT 1 FROM sqlite_master WHERE name='state'").fetchone())
    def test_missing_control_history_table_is_not_silently_recreated(self):
        with self.store.transaction() as db:db.execute('DROP TABLE recovery_requests')
        with self.assertRaisesRegex(Rejected,'recovery_schema'):RecoveryStore(self.root).initialize()
    def test_final_result_sql_is_rolled_back_when_budget_expires_before_commit(self):
        import time
        row=self.store.admit({**self.body,'timeout_seconds':1},self.writer)[0];self.store.begin('check')
        def delay_after_sql():
            while deadlines.now_ns()<=row['timing']['budget']['expires_boot_ns']:time.sleep(.005)
        self.store.commit_checkpoint=delay_after_sql
        with self.assertRaises(deadlines.Expired):self.store.finish('check','STORAGE_VERIFIED',{'storage_verified':True})
        result=self.store.get('check');self.assertEqual(result['state'],'RUNNING');self.assertIsNone(result['result'])
    def test_missing_control_version_is_not_implicitly_reset(self):
        with self.store.transaction() as db:db.execute('DELETE FROM recovery_meta')
        with self.assertRaisesRegex(Rejected,'recovery_schema'):RecoveryStore(self.root).initialize()
        with sqlite3.connect(self.store.path) as db:self.assertEqual(db.execute('SELECT * FROM recovery_meta').fetchall(),[])

    def test_malformed_persistent_budget_never_disables_deadline(self):
        import copy
        row=self.store.admit(self.body,self.writer)[0];original=row['timing']
        bad=[]
        for budget in [None,{},dict(original['budget'],seconds=True),dict(original['budget'],seconds=11),dict(original['budget'],expires_boot_ns=original['budget']['expires_boot_ns']+1),dict(original['budget'],accepted_boot_ns=-1),dict(original['budget'],version=2)]:
            bad.append(dict(original,budget=budget))
        bad.extend([dict(original,authority=None),dict(original,authority={'gate_epoch':original['authority']['gate_epoch']}),dict(original,authority=dict(original['authority'],gate_revision=True))])
        # A structurally valid but different timeout must also match the immutable digest.
        changed=copy.deepcopy(original);changed['budget']['seconds']=9;changed['budget']['expires_boot_ns']=changed['budget']['accepted_boot_ns']+9_000_000_000;bad.append(changed)
        for timing in bad:
            with self.subTest(timing=timing):
                with self.store.transaction() as db:db.execute('UPDATE recovery_requests SET timing=?',(json.dumps(timing),))
                with self.assertRaisesRegex(Rejected,'recovery_schema'):self.store.get('check')
                with self.assertRaisesRegex(Rejected,'recovery_schema'):RecoveryStore(self.root).initialize()
                with patch('certweft.recovery.filesystem_probe',side_effect=AssertionError('must not probe')):
                    with self.assertRaisesRegex(Rejected,'recovery_schema'):verify(self.config,'check')
                with sqlite3.connect(self.store.path) as db:self.assertEqual(db.execute('SELECT state FROM recovery_requests').fetchone()[0],'ACCEPTED')
        self.assertEqual(self.gate.read()['state'],'VERIFY_REQUIRED')
