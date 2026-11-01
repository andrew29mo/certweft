"""Ledger/authority tests only; real certificates and TLS are exercised in the VM."""
import contextlib,json,os,sqlite3,tempfile,time,unittest
from pathlib import Path
from certweft.core import Rejected
from certweft import deadlines
from certweft.gate import Gate
from certweft.recovery import RecoveryStore
import test_recovery as recovery_tests

class ClosedRecoveryLedger(unittest.TestCase):
    setUp=recovery_tests.DurableVerification.setUp
    tearDown=recovery_tests.DurableVerification.tearDown
    def proof(self,seconds=10):
        body={**self.body,'op':'recover-certificate','timeout_seconds':seconds}
        row=self.store.admit(body,self.writer)[0];self.store.begin('check')
        self.store.finish('check','CERTIFICATE_VERIFIED',{'fixture_proof':True,'updates_enabled':False})
        return body,row
    def test_operation_kind_cannot_reinterpret_existing_id(self):
        self.store.admit(self.body,self.writer)
        with self.assertRaisesRegex(Rejected,'request_conflict'):self.store.admit({**self.body,'op':'recover-certificate'},self.writer)
    def test_paired_completion_stays_closed_and_does_not_change_main_state(self):
        body,row=self.proof();before=self.writer.status()
        result=self.store.complete_closed('check',{'fixture_proof':True,'updates_enabled':False})
        self.assertEqual(result['state'],'VERIFIED_CLOSED');gate=self.gate.read();self.assertEqual(gate['state'],'VERIFIED_CLOSED')
        self.assertTrue(self.store.completion_recorded(gate));self.assertFalse(self.store.admit(body,self.writer)[1])
        self.assertEqual(self.writer.status(),before)
        with self.assertRaises(Rejected):self.gate.require(Gate.token(gate))
        self.assertEqual(self.gate.start()['state'],'RECOVERY_REQUIRED')
    def test_final_expiry_cannot_commit_closed_result(self):
        body,row=self.proof(1)
        def delay(point):
            if point=='closed-result-commit':
                while deadlines_now()<=row['timing']['budget']['expires_boot_ns']:time.sleep(.005)
        with self.assertRaises(deadlines.Expired):self.store.complete_closed('check',{'fixture_proof':True},delay)
        self.assertEqual(self.store.get('check')['state'],'CERTIFICATE_VERIFIED')
        self.assertEqual(self.gate.read()['state'],'VERIFY_REQUIRED');self.assertFalse(self.store.completion_recorded(self.gate.read()))
    def test_late_completion_cannot_demote_a_newer_gate(self):
        self.proof();newer=[]
        def replace(point):
            if point=='closed-gate-published':newer.append(self.gate.start())
        with self.assertRaisesRegex(Rejected,'stale_gate_authority'):self.store.complete_closed('check',{'fixture_proof':True},replace)
        self.assertEqual(self.gate.read(),newer[0]);self.assertEqual(self.store.get('check')['state'],'CERTIFICATE_VERIFIED')
    def test_interrupted_proof_is_not_automatically_completed(self):
        _,row=self.proof();self.gate.start();self.assertTrue(self.store.reconcile())
        result=self.store.get('check');self.assertEqual(result['state'],'INTERRUPTED');self.assertEqual(result['timing'],row['timing'])
    def legacy(self,malformed=False):
        self.store.admit(self.body,self.writer);self.store.finish('check','FAILED',{'fixture':True})
        original=self.store.get('check')
        with contextlib.closing(sqlite3.connect(self.store.path)) as db:values=list(db.execute('SELECT id,digest,state,timing,target,probe,result FROM recovery_requests').fetchone())
        if malformed:
            timing=json.loads(values[3]);timing['budget']=None;values[3]=json.dumps(timing)
        directory=self.root/'legacy';directory.mkdir(mode=0o700);path=directory/'recovery.db'
        with contextlib.closing(sqlite3.connect(path)) as db,db:
            db.execute('CREATE TABLE recovery_meta(version INTEGER NOT NULL)');db.execute('INSERT INTO recovery_meta VALUES(1)')
            db.execute('CREATE TABLE recovery_requests(id TEXT PRIMARY KEY,digest TEXT NOT NULL,state TEXT NOT NULL,timing TEXT NOT NULL,target TEXT NOT NULL,probe TEXT NOT NULL,result TEXT)');db.execute('INSERT INTO recovery_requests VALUES(?,?,?,?,?,?,?)',values)
        os.chmod(path,0o600);return RecoveryStore(directory),original
    def test_v1_migration_preserves_old_digest_budget_and_result(self):
        legacy,original=self.legacy();legacy.initialize();self.assertEqual(legacy.get('check'),original)
        with contextlib.closing(sqlite3.connect(legacy.path)) as db:self.assertEqual(db.execute('SELECT version FROM recovery_meta').fetchone()[0],2)
    def test_malformed_v1_migration_rolls_back_instead_of_repair(self):
        legacy,_=self.legacy(True)
        with self.assertRaisesRegex(Rejected,'recovery_schema'):legacy.initialize()
        with contextlib.closing(sqlite3.connect(legacy.path)) as db:
            self.assertEqual(db.execute('SELECT version FROM recovery_meta').fetchone()[0],1)
            self.assertEqual(len(db.execute('PRAGMA table_info(recovery_requests)').fetchall()),7)

def deadlines_now():
    from certweft.deadlines import now_ns
    return now_ns()
