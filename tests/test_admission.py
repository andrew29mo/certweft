"""Real SQL admission boundaries; formal TLS and service coverage is in the VM."""
import json,sqlite3,time,unittest
from unittest.mock import patch
from certweft import deadlines
from certweft.admission import open_updates,record,effective_budget,expected
from certweft.core import Rejected
from certweft.gate import Gate
from certweft.opening import require_updates
from certweft.operations import Operations
from certweft.reconciliation import digest
import test_release as fixtures

class AdmissionLedger(unittest.TestCase):
    setUp=fixtures.ReleaseLedger.setUp
    tearDown=fixtures.ReleaseLedger.tearDown
    close=fixtures.ReleaseLedger.close
    db=fixtures.ReleaseLedger.db
    run_main=fixtures.ReleaseLedger.run_main
    prepared=fixtures.ReleaseLedger.prepared
    source=fixtures.ReleaseLedger.source
    run_release=fixtures.ReleaseLedger.run_release
    def ready(self,source_seconds=10,release_seconds=10,own_seconds=10):
        self.source(source_seconds);self.body_release['timeout_seconds']=release_seconds
        self.store.admit(self.body_release,self.writer);r=self.run_release();self.assertEqual(r['state'],'RELEASE_VERIFIED_CLOSED')
        self.body_open_updates={'op':'open-updates','request_id':'reopen','release_request_id':'release','release_receipt_digest':r['result']['receipt_digest'],'timeout_seconds':own_seconds,**Gate.token(self.gate.read())}
        return self.store.admit(self.body_open_updates,self.writer)[0]
    def run_open(self,checkpoint=lambda point:None):
        with patch('certweft.admission.FixedWriter.check',return_value='c'*64),patch('certweft.admission.FixedWriter.confirm',return_value='c'*64):return open_updates(self.config,'reopen',checkpoint)
    def allowed(self):return require_updates(self.root,Gate.token(self.gate.read()))
    def test_full_pair_opens_without_rewriting_degraded_and_deduplicates(self):
        row=self.ready()
        with self.db() as d:before=d.execute('SELECT * FROM requests').fetchall()
        out=self.run_open();self.assertEqual(out['state'],'OPENED');self.assertTrue(self.allowed())
        self.assertEqual(self.store.admit(self.body_open_updates,self.writer),(out,False))
        with self.assertRaisesRegex(Rejected,'request_conflict'):self.store.admit(dict(self.body_open_updates,timeout_seconds=9),self.writer)
        with self.db() as d:self.assertEqual(d.execute('SELECT * FROM requests').fetchall(),before)
        self.assertEqual(row['timing'],out['timing'])
    def test_gate_and_main_without_final_root_commit_never_open(self):
        self.ready();seen=[]
        def check(point):
            if point=='admission-gate-published':
                with self.assertRaises(Rejected):self.allowed()
                seen.append(point)
        self.assertEqual(self.run_open(check)['state'],'OPENED');self.assertEqual(len(seen),1)
    def test_deadline_at_final_commit_does_not_half_open(self):
        row=self.ready(own_seconds=1)
        def wait(point):
            if point=='admission-result-commit':
                while deadlines.now_ns()<=row['timing']['budget']['expires_boot_ns']:time.sleep(.005)
        out=self.run_open(wait);self.assertEqual(out['state'],'EXPIRED')
        with self.assertRaises(Rejected):self.allowed()
        self.assertFalse(out['result']['updates_enabled'])
    def test_source_and_release_cap_own_deadline(self):
        row=self.ready(source_seconds=1)
        self.assertEqual(effective_budget(row)['expires_boot_ns'],row['target']['release_target']['source_budget']['expires_boot_ns'])
    def test_release_expiry_cannot_be_extended_by_new_operation(self):
        row=self.ready(release_seconds=1)
        def wait(point):
            if point=='admission-main-committed':
                while deadlines.now_ns()<=row['target']['release_budget']['expires_boot_ns']:time.sleep(.005)
        self.assertEqual(self.run_open(wait)['state'],'EXPIRED')
        with self.assertRaises(Rejected):self.allowed()
    def test_stale_gate_after_main_commit_not_overwritten(self):
        self.ready();new=[]
        def replace(point):
            if point=='admission-main-committed':new.append(self.gate.start())
        self.assertEqual(self.run_open(replace)['state'],'FAILED');self.assertEqual(self.gate.read(),new[0])
    def test_stale_gate_before_final_root_commit_not_overwritten(self):
        self.ready();new=[]
        def replace(point):
            if point=='admission-result-commit':new.append(self.gate.start())
        self.assertEqual(self.run_open(replace)['state'],'FAILED');self.assertEqual(self.gate.read(),new[0])
    def test_newer_main_record_not_overwritten_by_late_completion(self):
        self.ready();new=[]
        def replace(point):
            if point=='admission-gate-published':
                with self.db() as d,d:
                    r=record(d);r['request_id']='newer';new.append(r);d.execute('UPDATE admission_release SET record=?',(json.dumps(r),))
        self.assertEqual(self.run_open(replace)['state'],'FAILED')
        with self.db() as d:self.assertEqual(record(d),new[0])
    def test_new_degraded_row_revokes_existing_permission(self):
        self.ready();self.assertEqual(self.run_open()['state'],'OPENED')
        with self.db() as d,d:d.execute("INSERT INTO requests VALUES('new-fault',?,'DEGRADED',NULL,NULL)",('a'*64,))
        with self.assertRaisesRegex(Rejected,'unresolved_degraded'):self.allowed()
    def test_changed_referenced_degraded_row_not_exempt(self):
        self.ready();self.assertEqual(self.run_open()['state'],'OPENED')
        with self.db() as d,d:d.execute("UPDATE requests SET result='{}' WHERE state='DEGRADED'")
        with self.assertRaisesRegex(Rejected,'unresolved_degraded'):self.allowed()
    def test_restart_preserves_budgets_but_does_not_replay_opening(self):
        row=self.ready();self.store.begin('reopen');self.gate.start();self.store.reconcile();out=self.store.get('reopen')
        self.assertEqual(out['state'],'INTERRUPTED');self.assertEqual(out['timing'],row['timing']);self.assertEqual(out['target'],row['target'])
        self.assertFalse(self.store.admit(self.body_open_updates,self.writer)[1])
    def test_completed_opening_cannot_authorize_new_session(self):
        self.ready();out=self.run_open();self.gate.start()
        with self.assertRaises(Rejected):self.allowed()
        self.assertEqual(self.store.admit(self.body_open_updates,self.writer),(out,False))
    def test_real_sqlite_full_before_publication(self):
        self.ready()
        with self.db() as d,d:
            d.execute('CREATE TABLE pressure(data BLOB)');d.execute('CREATE TRIGGER pressure_probe BEFORE UPDATE ON storage_probe BEGIN INSERT INTO pressure VALUES(zeroblob(1048576)); END');self.config['sqlite_max_pages']=d.execute('PRAGMA page_count').fetchone()[0]+1
        out=self.run_open();self.assertEqual(out['state'],'FAILED');self.assertEqual(out['result']['sqlite_error'],'SQLITE_FULL')
        with self.assertRaises(Rejected):self.allowed()
    def candidate(self,db):
        state=json.loads(db.execute('SELECT data FROM state').fetchone()[0]);target={**state,'revision':state['revision']+1}
        timing={'activation':deadlines.create(10),'recovery':None}
        db.execute("INSERT INTO requests VALUES('valid-commit',?,'RUNNING',NULL,?)",('b'*64,json.dumps(timing)));db.commit()
        return state,target
    def test_main_only_receipt_cannot_admit_or_commit(self):
        row=self.ready();self.store.begin('reopen')
        with self.db() as d:
            d.execute('CREATE TABLE admission_release(id INTEGER PRIMARY KEY,record TEXT)');d.execute('INSERT INTO admission_release VALUES(1,?)',(json.dumps(expected(row)),));d.commit()
            before,target=self.candidate(d);reached=[]
            with self.assertRaisesRegex(Rejected,'^recovery_required$'):
                Operations.commit(d,'valid-commit',target,lambda:reached.append(True),gate_authority=Gate.token(self.gate.read()))
            d.rollback()
            self.assertFalse(reached,'commit_checkpoint_reached_before_admission')
            self.assertEqual(json.loads(d.execute('SELECT data FROM state').fetchone()[0]),before)
            self.assertEqual(d.execute("SELECT state,result FROM requests WHERE id='valid-commit'").fetchone(),('RUNNING',None))
    def test_commit_second_guard_rejects_gate_change_after_sql_writes(self):
        self.ready();self.assertEqual(self.run_open()['state'],'OPENED');authority=Gate.token(self.gate.read());new=[]
        with self.db() as d:
            before,target=self.candidate(d)
            def crossing():new.append(self.gate.start())
            with self.assertRaisesRegex(Rejected,'^stale_gate_authority$'):
                Operations.commit(d,'valid-commit',target,crossing,gate_authority=authority)
            d.rollback()
            self.assertEqual(len(new),1);self.assertEqual(self.gate.read(),new[0])
            self.assertEqual(json.loads(d.execute('SELECT data FROM state').fetchone()[0]),before)
            self.assertEqual(d.execute("SELECT state,result FROM requests WHERE id='valid-commit'").fetchone(),('RUNNING',None))
    def test_expiry_after_durable_root_result_closes_instead_of_adopting(self):
        row=self.ready(own_seconds=1)
        def wait(point):
            if point=='admission-result-committed':
                while deadlines.now_ns()<=row['timing']['budget']['expires_boot_ns']:time.sleep(.005)
        with self.assertRaisesRegex(Rejected,'opening_result_uncertain'):self.run_open(wait)
        self.assertEqual(self.store.get('reopen')['state'],'OPENED')
        with self.assertRaises(Rejected):self.allowed()
