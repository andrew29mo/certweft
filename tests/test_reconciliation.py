"""SQL/authority contracts only. Formal service + TLS is qualified by reconcile_vm."""
import contextlib,copy,json,sqlite3,time,unittest,uuid
from certweft import deadlines
from certweft.core import Rejected
from certweft.gate import Gate
from certweft.reconciliation import reconcile_main,snapshot,digest,receipt,completion_recorded
import test_recovery as fixtures

class ClosedPreparation(unittest.TestCase):
    setUp=fixtures.DurableVerification.setUp
    tearDown=fixtures.DurableVerification.tearDown
    def close(self):
        body={**self.body,'op':'recover-certificate','request_id':'certificate'}
        self.store.admit(body,self.writer);self.store.begin('certificate')
        proof={'committed':self.state['committed'],'tls_confirmed':True,'restored':True,'updates_enabled':False}
        self.store.finish('certificate','CERTIFICATE_VERIFIED',proof);self.store.complete_closed('certificate',proof)
        self.prepare={**self.body,'op':'reconcile-closed','request_id':'prepare','certificate_request_id':'certificate',**Gate.token(self.gate.read())}
    def db(self):return contextlib.closing(sqlite3.connect(self.root/'journal.db'))
    def run_main(self,row,checkpoint=lambda point:None):
        with deadlines.use(row['timing']['budget']),self.db() as db:return reconcile_main(db,self.writer,row,checkpoint)
    def test_admission_dedup_kind_conflict_and_closed_proof_required(self):
        self.close();row,created=self.store.admit(self.prepare,self.writer);self.assertTrue(created)
        self.assertEqual(self.store.admit(self.prepare,self.writer),(row,False))
        with self.assertRaisesRegex(Rejected,'request_conflict'):self.store.admit({**self.prepare,'timeout_seconds':9},self.writer)
        with self.assertRaisesRegex(Rejected,'request_conflict'):self.store.admit({**self.body,'request_id':'prepare'},self.writer)
        self.gate.start()
        with self.assertRaisesRegex(Rejected,'stale_gate_authority'):self.store.admit({**self.prepare,'request_id':'old'},self.writer)
    def test_incomplete_certificate_publication_not_admissible(self):
        self.close()
        with self.store.transaction() as db:db.execute("UPDATE recovery_requests SET state='FAILED' WHERE id='certificate'")
        with self.assertRaisesRegex(Rejected,'certificate_completion_required'):self.store.admit(self.prepare,self.writer)
    def test_main_atomic_health_reset_interrupts_live_but_preserves_terminal(self):
        self.close()
        with self.db() as db,db:
            for identity,status in [('live','RUNNING'),('bad','DEGRADED'),('done','COMMITTED')]:
                db.execute('INSERT INTO requests VALUES(?,?,?,?,NULL)',(identity,'a'*64,status,json.dumps({'historical':True})))
            db.execute("UPDATE health SET state='STORAGE_FAILED',detail='old' WHERE id=1")
        row=self.store.admit(self.prepare,self.writer)[0];self.store.begin('prepare')
        record,after=self.run_main(row)
        with self.db() as db:
            states={r[0]:r[1:] for r in db.execute('SELECT id,state,result FROM requests')}
            self.assertEqual(states['live'][0],'INTERRUPTED');self.assertEqual(json.loads(states['live'][1])['execution_outcome'],'unknown')
            for identity,status in [('bad','DEGRADED'),('done','COMMITTED')]:self.assertEqual(states[identity],(status,'{"historical": true}'))
            self.assertEqual(db.execute('SELECT state,detail FROM health').fetchone(),('HEALTHY',None));self.assertEqual(digest(snapshot(db)),after)
            self.assertEqual(receipt(db),json.loads(json.dumps(record)))
        self.assertEqual(self.writer.status()['state'],'READY');self.assertNotEqual(self.writer.status()['epoch'],self.state['epoch'])
        self.assertFalse(completion_recorded(self.root,self.gate.read(),self.store))
        self.store.finish('prepare','JOURNAL_VERIFIED_CLOSED',{'receipt_digest':digest(record),'after_digest':after,'closed_gate':Gate.token(self.gate.read()),'updates_enabled':False})
        self.assertTrue(completion_recorded(self.root,self.gate.read(),self.store))
        with self.assertRaises(Rejected):self.gate.require(Gate.token(self.gate.read()))
    def test_snapshot_drift_before_commit_rolls_back(self):
        self.close();row=self.store.admit(self.prepare,self.writer)[0];self.store.begin('prepare')
        with self.db() as db,db:db.execute("UPDATE health SET state='STORAGE_FAILED'")
        with self.assertRaisesRegex(Rejected,'journal_drift'):self.run_main(row)
        with self.db() as db:self.assertIsNone(receipt(db));self.assertEqual(db.execute('SELECT state FROM health').fetchone()[0],'STORAGE_FAILED')
    def test_expiry_after_sql_rolls_back_all_main_changes(self):
        self.close();row=self.store.admit({**self.prepare,'timeout_seconds':1},self.writer)[0];self.store.begin('prepare')
        def wait(point):
            while deadlines.now_ns()<=row['timing']['budget']['expires_boot_ns']:time.sleep(.005)
        with self.assertRaises(deadlines.Expired):self.run_main(row,wait)
        self.assertEqual(self.writer.status(),self.state)
        with self.db() as db:self.assertIsNone(receipt(db))
    def test_stale_gate_at_main_commit_rolls_back(self):
        self.close();row=self.store.admit(self.prepare,self.writer)[0];self.store.begin('prepare')
        newer=[]
        with self.assertRaisesRegex(Rejected,'stale_gate_authority'):self.run_main(row,lambda point:newer.append(self.gate.start()))
        self.assertEqual(self.gate.read(),newer[0]);self.assertEqual(self.writer.status(),self.state)
    def test_main_committed_without_root_result_never_qualifies_after_restart(self):
        self.close();row=self.store.admit(self.prepare,self.writer)[0];self.store.begin('prepare');self.run_main(row)
        self.assertFalse(completion_recorded(self.root,self.gate.read(),self.store))
        self.gate.start();self.store.reconcile();now=self.store.get('prepare')
        self.assertEqual(now['state'],'INTERRUPTED');self.assertEqual(now['timing'],row['timing']);self.assertFalse(self.store.admit(self.prepare,self.writer)[1])
        self.assertFalse(completion_recorded(self.root,self.gate.read(),self.store))
    def test_unknown_receipt_is_not_overwritten(self):
        self.close()
        with self.db() as db,db:
            db.execute('CREATE TABLE closed_reconciliation(id INTEGER PRIMARY KEY,record TEXT)');db.execute("INSERT INTO closed_reconciliation VALUES(1,'{}')")
        row=self.store.admit(self.prepare,self.writer)[0];self.store.begin('prepare')
        with self.assertRaisesRegex(Rejected,'reconciliation_schema'):self.run_main(row)
        with self.db() as db:self.assertEqual(db.execute('SELECT record FROM closed_reconciliation').fetchone()[0],'{}')

    def test_complete_keys_with_invalid_values_are_preserved_and_never_qualify(self):
        self.close();row=self.store.admit(self.prepare,self.writer)[0];self.store.begin('prepare')
        base={'version':1,'request_id':'prepare','request_digest':row['digest'],'gate':row['timing']['authority'],'certificate_request_id':'certificate','committed':self.state['committed'],'prior_journal_digest':row['target']['journal_digest'],'core_after':self.state,'interrupted':[],'resolved_degraded':[]}
        with self.db() as db,db:db.execute('CREATE TABLE closed_reconciliation(id INTEGER PRIMARY KEY,record TEXT)')
        mutations=[('request_id',None),('request_id',[]),('request_digest',None),('certificate_request_id',None),('certificate_request_id','prepare'),('committed',None),('prior_journal_digest',None),('gate',{}),('gate',{'gate_epoch':'a'*32,'gate_revision':True}),('gate',{'gate_epoch':'a'*32,'gate_revision':2**63-1}),('core_after',{}),('interrupted',[['live',[]]]),('interrupted',[['live','COMMITTED']]),('interrupted',[['live','RUNNING'],['other','ACCEPTED']]),('resolved_degraded',[None]),('resolved_degraded',['same','same']),('resolved_degraded',['b','a'])]
        for field,value in mutations:
            damaged=copy.deepcopy(base);damaged[field]=value
            with self.subTest(field=field,value=value):
                encoded=json.dumps(damaged)
                with self.db() as db,db:db.execute('INSERT OR REPLACE INTO closed_reconciliation VALUES(1,?)',(encoded,))
                with self.db() as db:
                    with self.assertRaisesRegex(Rejected,'reconciliation_schema'):receipt(db)
                self.assertFalse(completion_recorded(self.root,self.gate.read(),self.store))
                with self.assertRaisesRegex(Rejected,'reconciliation_schema'):self.run_main(row)
                self.assertEqual(self.writer.status(),self.state)
                with self.db() as db:self.assertEqual(db.execute('SELECT record FROM closed_reconciliation').fetchone()[0],encoded)
        for field,value in [('schema',True),('state','APPLYING'),('candidate','a'*32),('epoch',None),('revision',True),('revision',2**63-1),('committed','a'*32),('committed_digest','not-a-digest')]:
            damaged=copy.deepcopy(base);damaged['core_after'][field]=value
            with self.subTest(core_field=field):
                with self.db() as db,db:db.execute('UPDATE closed_reconciliation SET record=?',(json.dumps(damaged),))
                with self.assertRaisesRegex(Rejected,'reconciliation_schema'):self.run_main(row)
