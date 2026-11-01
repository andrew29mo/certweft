"""Opening SQL/authority contracts. TLS fixture evidence is in the VM matrix."""
import contextlib,json,sqlite3,time,unittest
from unittest.mock import patch
from certweft import deadlines
from certweft.core import Rejected
from certweft.gate import Gate
from certweft.operations import Operations
from certweft.opening import prepare_opening,ready_closed,require_updates,marker,digest,expected_marker
import test_reconciliation as fixtures

class OpeningLedger(unittest.TestCase):
    setUp=fixtures.ClosedPreparation.setUp
    tearDown=fixtures.ClosedPreparation.tearDown
    close=fixtures.ClosedPreparation.close
    db=fixtures.ClosedPreparation.db
    run_main=fixtures.ClosedPreparation.run_main
    def prepared(self,degraded=False):
        self.close()
        if degraded:
            with self.db() as db,db:db.execute("INSERT INTO requests VALUES('old-degraded',?,'DEGRADED',?,NULL)",('a'*64,json.dumps({'old':True})))
        row=self.store.admit(self.prepare,self.writer)[0];self.store.begin('prepare')
        record,after=self.run_main(row)
        proof={'receipt_digest':digest(record),'after_digest':after,'closed_gate':Gate.token(self.gate.read()),'journal_reconciled':True,'health_verified':True,'main_committed':True,'committed':self.state['committed'],'updates_enabled':False}
        self.store.finish('prepare','JOURNAL_VERIFIED_CLOSED',proof)
        self.body_open={'op':'prepare-opening','request_id':'opening','preparation_request_id':'prepare','receipt_digest':digest(record),'core_epoch':record['core_after']['epoch'],'core_revision':record['core_after']['revision'],'timeout_seconds':10,**Gate.token(self.gate.read())}
    def test_real_sql_pair_degraded_references_and_dedup_remain_closed(self):
        self.prepared(True)
        with self.db() as db:before=db.execute('SELECT * FROM requests').fetchall()
        original=self.store.admit(self.body_open,self.writer)[0];out=prepare_opening(self.config,'opening')
        self.assertEqual(out['state'],'OPENING_VERIFIED_CLOSED');self.assertTrue(ready_closed(self.root,self.gate.read(),self.store))
        self.assertEqual(out['target']['degraded_references'].keys(),{'old-degraded'})
        self.assertEqual(self.store.admit(self.body_open,self.writer),(out,False));self.assertEqual(out['timing'],original['timing'])
        with self.assertRaisesRegex(Rejected,'request_conflict'):self.store.admit({**self.body_open,'timeout_seconds':9},self.writer)
        with self.db() as db:self.assertEqual(db.execute('SELECT * FROM requests').fetchall(),before)
        with self.assertRaises(Rejected):require_updates(self.root,Gate.token(self.gate.read()))
    def test_unreferenced_or_changed_degraded_history_is_rejected(self):
        self.prepared(True)
        with self.db() as db,db:db.execute("INSERT INTO requests VALUES('new-degraded',?,'DEGRADED',NULL,NULL)",('b'*64,))
        with self.assertRaisesRegex(Rejected,'unreferenced_degraded_history'):self.store.admit(self.body_open,self.writer)
        with self.db() as db,db:
            db.execute("DELETE FROM requests WHERE id='new-degraded'");db.execute("UPDATE requests SET result='{}' WHERE id='old-degraded'")
        with self.assertRaisesRegex(Rejected,'preparation_journal_drift'):self.store.admit(self.body_open,self.writer)
    def test_wrong_receipt_core_and_incomplete_preparation_never_admit(self):
        self.prepared()
        for bad in [dict(self.body_open,receipt_digest='0'*64),dict(self.body_open,core_revision=self.body_open['core_revision']+1)]:
            with self.assertRaises(Rejected):self.store.admit(bad,self.writer)
        with self.store.transaction() as db:db.execute("UPDATE recovery_requests SET state='FAILED' WHERE id='prepare'")
        with self.assertRaisesRegex(Rejected,'completed_preparation_required'):self.store.admit(self.body_open,self.writer)
    def test_expiry_before_main_commit_rolls_back_marker(self):
        self.prepared();row=self.store.admit({**self.body_open,'timeout_seconds':1},self.writer)[0]
        def wait(point):
            if point=='opening-main-commit':
                while deadlines.now_ns()<=row['timing']['budget']['expires_boot_ns']:time.sleep(.005)
        out=prepare_opening(self.config,'opening',wait);self.assertEqual(out['state'],'EXPIRED')
        with self.db() as db:self.assertIsNone(marker(db))
    def test_expiry_after_marker_commit_never_completes(self):
        self.prepared();row=self.store.admit({**self.body_open,'timeout_seconds':1},self.writer)[0]
        def wait(point):
            if point=='opening-result-commit':
                while deadlines.now_ns()<=row['timing']['budget']['expires_boot_ns']:time.sleep(.005)
        out=prepare_opening(self.config,'opening',wait);self.assertEqual(out['state'],'EXPIRED')
        self.assertFalse(ready_closed(self.root,self.gate.read(),self.store))
        with self.db() as db:self.assertIsNotNone(marker(db))
    def test_late_result_cannot_replace_newer_marker(self):
        self.prepared();self.store.admit(self.body_open,self.writer);changed=[]
        def replace(point):
            if point=='opening-main-committed':
                with self.db() as db,db:
                    newer=marker(db);newer['request_id']='newer-root-intent';changed.append(newer)
                    db.execute('UPDATE opening_intent SET record=?',(json.dumps(newer),))
        out=prepare_opening(self.config,'opening',replace);self.assertEqual(out['state'],'FAILED');self.assertEqual(out['result']['reason'],'stale_opening_marker')
        with self.db() as db:self.assertEqual(marker(db),changed[0])
    def test_restart_keeps_original_budget_and_never_replays_intent(self):
        self.prepared();row=self.store.admit(self.body_open,self.writer)[0];self.store.begin('opening')
        self.gate.start();self.store.reconcile();out=self.store.get('opening')
        self.assertEqual(out['state'],'INTERRUPTED');self.assertEqual(out['timing'],row['timing']);self.assertFalse(self.store.admit(self.body_open,self.writer)[1])
        with self.assertRaisesRegex(Rejected,'stale_gate_authority'):self.store.admit({**self.body_open,'request_id':'old'},self.writer)
    def test_valid_historical_intent_expires_without_becoming_permission(self):
        self.prepared();self.store.admit(self.body_open,self.writer);out=prepare_opening(self.config,'opening')
        budget=out['timing']['budget']
        with patch('certweft.deadlines.now_ns',return_value=budget['expires_boot_ns']+1),patch('certweft.deadlines.time.time_ns',return_value=budget['accepted_wall_ns']+budget['seconds']*10**9+1):
            self.assertFalse(ready_closed(self.root,self.gate.read(),self.store));self.assertEqual(self.store.get('opening'),out)
    def test_bootstrap_guard_fails_closed_with_missing_or_recovery_metadata(self):
        self.prepared();self.store.admit(self.body_open,self.writer);prepare_opening(self.config,'opening')
        current=self.gate.read();forged=self.gate.write({**current,'state':'RUNNING','reason':'session_started'})
        with self.assertRaisesRegex(Rejected,'opening_handoff_required'):require_updates(self.root,Gate.token(forged))
        with self.db() as db:
            with self.assertRaisesRegex(Rejected,'opening_handoff_required'):Operations.commit(db,'missing',{},gate_authority=Gate.token(forged))
        self.store.path.unlink()
        with self.assertRaises(FileNotFoundError):require_updates(self.root,Gate.token(forged))
    def test_malformed_existing_marker_is_preserved(self):
        self.prepared();self.store.admit(self.body_open,self.writer)
        with self.db() as db,db:
            db.execute('CREATE TABLE opening_intent(id INTEGER PRIMARY KEY,record TEXT)');db.execute("INSERT INTO opening_intent VALUES(1,'{}')")
        out=prepare_opening(self.config,'opening');self.assertEqual(out['state'],'FAILED');self.assertEqual(out['result']['reason'],'opening_marker_schema')
        with self.db() as db:self.assertEqual(db.execute('SELECT record FROM opening_intent').fetchone()[0],'{}')

    def test_readiness_validation_crossing_actual_expiry_never_reports_ready(self):
        self.prepared();self.store.admit(dict(self.body_open,timeout_seconds=1),self.writer)
        out=prepare_opening(self.config,'opening');self.assertEqual(out['state'],'OPENING_VERIFIED_CLOSED')
        from certweft import opening
        original=opening.check_pair;ran=[]
        def slow_validation(*args):
            while deadlines.now_ns()<=out['timing']['budget']['expires_boot_ns']:time.sleep(.005)
            original(*args);ran.append(True)
        with patch('certweft.opening.check_pair',side_effect=slow_validation):
            self.assertFalse(ready_closed(self.root,self.gate.read(),self.store))
        self.assertTrue(ran);self.assertGreater(deadlines.now_ns(),out['timing']['budget']['expires_boot_ns'])
        self.assertEqual(self.store.get('opening'),out)
        with self.assertRaises(Rejected):require_updates(self.root,Gate.token(self.gate.read()))
