"""Release SQL/deadline contracts; cryptography is covered by the formal VM."""
import json,sqlite3,time,unittest
from unittest.mock import patch
from certweft import deadlines
from certweft.core import Rejected
from certweft.gate import Gate
from certweft.opening import prepare_opening
from certweft.release import prepare_release,receipt,ready_closed,effective_budget
from certweft.reconciliation import digest
import test_opening as fixtures

class ReleaseLedger(unittest.TestCase):
    setUp=fixtures.OpeningLedger.setUp
    tearDown=fixtures.OpeningLedger.tearDown
    close=fixtures.OpeningLedger.close
    db=fixtures.OpeningLedger.db
    run_main=fixtures.OpeningLedger.run_main
    prepared=fixtures.OpeningLedger.prepared
    def source(self,seconds=10):
        self.prepared(True);self.config['master']={}
        for field in ['key','conf','ca']:
            path=self.root/('fixture-'+field);path.write_text('unit fixture');path.chmod(0o600);self.config['writer'][field]=str(path)
        self.store.admit(dict(self.body_open,timeout_seconds=seconds),self.writer)
        opened=prepare_opening(self.config,'opening');self.assertEqual(opened['state'],'OPENING_VERIFIED_CLOSED')
        self.body_release={'op':'prepare-release','request_id':'release','opening_request_id':'opening','opening_marker_digest':opened['result']['marker_digest'],'timeout_seconds':10,**Gate.token(self.gate.read())}
        return opened
    def run_release(self,checkpoint=lambda point:None):
        with patch('certweft.release.FixedWriter.check',return_value='c'*64),patch('certweft.release.FixedWriter.confirm',return_value='c'*64):return prepare_release(self.config,'release',checkpoint)
    def test_paired_fresh_sql_success_stays_closed_and_deduplicates(self):
        source=self.source();row=self.store.admit(self.body_release,self.writer)[0]
        with self.db() as db:before=db.execute('SELECT * FROM requests').fetchall()
        out=self.run_release();self.assertEqual(out['state'],'RELEASE_VERIFIED_CLOSED');self.assertTrue(ready_closed(self.root,self.gate.read()))
        self.assertEqual(row['target']['source_budget'],source['timing']['budget']);self.assertEqual(self.store.admit(self.body_release,self.writer),(out,False))
        with self.assertRaisesRegex(Rejected,'request_conflict'):self.store.admit(dict(self.body_release,timeout_seconds=9),self.writer)
        with self.db() as db:self.assertEqual(db.execute('SELECT * FROM requests').fetchall(),before)
        self.assertEqual(self.gate.read()['state'],'VERIFIED_CLOSED')
    def test_source_deadline_caps_longer_release_without_reset(self):
        source=self.source(1);row=self.store.admit(self.body_release,self.writer)[0]
        self.assertEqual(effective_budget(row)['expires_boot_ns'],source['timing']['budget']['expires_boot_ns'])
        def wait(point):
            if point=='release-main-committed':
                while deadlines.now_ns()<=source['timing']['budget']['expires_boot_ns']:time.sleep(.005)
        out=self.run_release(wait);self.assertEqual(out['state'],'EXPIRED');self.assertFalse(ready_closed(self.root,self.gate.read()))
        self.assertGreater(row['timing']['budget']['expires_boot_ns'],deadlines.now_ns());self.assertEqual(self.store.get('opening'),source)
        self.assertFalse(self.store.admit(self.body_release,self.writer)[1]);self.assertEqual(out['timing'],row['timing'])
    def test_own_expiry_before_receipt_commit_rolls_back(self):
        self.source();row=self.store.admit(dict(self.body_release,timeout_seconds=1),self.writer)[0]
        def wait(point):
            if point=='release-main-commit':
                while deadlines.now_ns()<=row['timing']['budget']['expires_boot_ns']:time.sleep(.005)
        self.assertEqual(self.run_release(wait)['state'],'EXPIRED')
        with self.db() as db:self.assertIsNone(receipt(db))
    def test_source_expiry_at_final_root_commit_cannot_complete(self):
        source=self.source(1);self.store.admit(self.body_release,self.writer)
        def wait(point):
            if point=='release-result-commit':
                while deadlines.now_ns()<=source['timing']['budget']['expires_boot_ns']:time.sleep(.005)
        out=self.run_release(wait);self.assertEqual(out['state'],'EXPIRED');self.assertFalse(ready_closed(self.root,self.gate.read()))
    def test_restart_reconciles_source_expiry_without_replay(self):
        source=self.source(1);row=self.store.admit(self.body_release,self.writer)[0];self.store.begin('release')
        while deadlines.now_ns()<=source['timing']['budget']['expires_boot_ns']:time.sleep(.005)
        self.gate.start();self.store.reconcile();out=self.store.get('release')
        self.assertEqual(out['state'],'EXPIRED');self.assertEqual(out['timing'],row['timing']);self.assertEqual(out['target'],row['target'])
        self.assertFalse(self.store.admit(self.body_release,self.writer)[1])
        with self.assertRaisesRegex(Rejected,'stale_gate_authority'):self.store.admit(dict(self.body_release,request_id='old'),self.writer)
    def test_sqlite_full_is_real_and_never_a_success(self):
        self.source();self.store.admit(self.body_release,self.writer)
        with self.db() as db,db:
            db.execute('CREATE TABLE pressure(data BLOB)');db.execute('CREATE TRIGGER full_probe BEFORE UPDATE ON storage_probe BEGIN INSERT INTO pressure VALUES(zeroblob(1048576)); END')
            self.config['sqlite_max_pages']=db.execute('PRAGMA page_count').fetchone()[0]+1
        out=self.run_release();self.assertEqual(out['state'],'FAILED');self.assertEqual(out['result']['sqlite_error'],'SQLITE_FULL');self.assertFalse(ready_closed(self.root,self.gate.read()))
    def test_stale_gate_cannot_publish_receipt(self):
        self.source();self.store.admit(self.body_release,self.writer);newer=[]
        def replace(point):
            if point=='release-main-commit':newer.append(self.gate.start())
        out=self.run_release(replace);self.assertEqual(out['state'],'FAILED');self.assertEqual(out['result']['reason'],'stale_gate_authority');self.assertEqual(self.gate.read(),newer[0])
        with self.db() as db:self.assertIsNone(receipt(db))
    def test_old_completion_cannot_overwrite_newer_receipt(self):
        self.source();self.store.admit(self.body_release,self.writer);newer=[]
        def replace(point):
            if point=='release-main-committed':
                with self.db() as db,db:
                    record=receipt(db);record['request_id']='newer-release';newer.append(record);db.execute('UPDATE release_preparation SET record=?',(json.dumps(record),))
        out=self.run_release(replace);self.assertEqual(out['state'],'FAILED');self.assertEqual(out['result']['reason'],'stale_release_receipt')
        with self.db() as db:self.assertEqual(receipt(db),newer[0])
    def test_malformed_source_budget_is_rejected_before_work(self):
        self.source();self.store.admit(self.body_release,self.writer)
        with self.store.transaction() as db:
            target=json.loads(db.execute("SELECT target FROM recovery_requests WHERE id='release'").fetchone()[0]);target['source_budget']=None
            db.execute("UPDATE recovery_requests SET target=? WHERE id='release'",(json.dumps(target),))
        with self.assertRaisesRegex(Rejected,'release_source_budget'):self.store.get('release')
    def test_malformed_prior_receipt_is_not_overwritten(self):
        self.source();self.store.admit(self.body_release,self.writer)
        with self.db() as db,db:db.execute('CREATE TABLE release_preparation(id INTEGER PRIMARY KEY,record TEXT)');db.execute("INSERT INTO release_preparation VALUES(1,'{}')")
        out=self.run_release();self.assertEqual(out['state'],'FAILED');self.assertEqual(out['result']['reason'],'release_receipt_schema')
        with self.db() as db:self.assertEqual(db.execute('SELECT record FROM release_preparation').fetchone()[0],'{}')
