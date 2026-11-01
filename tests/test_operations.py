import json,sqlite3,tempfile,unittest
from pathlib import Path
from certweft.operations import Operations,Cancelled
from certweft.core import Rejected
class DurableContracts(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.ops=Operations(self.root);self.ops.initialize()
        with sqlite3.connect(self.root/'journal.db') as db:db.execute('CREATE TABLE state(id INTEGER PRIMARY KEY,data TEXT)')
        self.body={'op':'submit','request_id':'one','certificate':'pem','epoch':'epoch','revision':1}
    def tearDown(self):self.temp.cleanup()
    def test_replay_and_conflict_survive_reopen(self):
        self.assertTrue(self.ops.admit(self.body)[1]);self.ops.begin('one');self.ops.finish('one','FAILED',{'reason':'test'})
        reopened=Operations(self.root);self.assertFalse(reopened.admit(self.body)[1])
        with self.assertRaisesRegex(Rejected,'request_conflict'):reopened.admit({**self.body,'revision':2})
    def test_cancel_wins_no_state_commit(self):
        self.ops.admit(self.body);self.ops.begin('one');self.ops.cancel('one')
        with sqlite3.connect(self.root/'journal.db') as db:
            with self.assertRaises(Cancelled):Operations.commit(db,'one',{'committed':'new'})
            db.rollback();self.assertIsNone(db.execute('SELECT * FROM state').fetchone())
        self.assertEqual(self.ops.get('one')['state'],'CANCEL_REQUESTED')
    def test_commit_wins_cancel_does_not_claim_success(self):
        self.ops.admit(self.body);self.ops.begin('one')
        with sqlite3.connect(self.root/'journal.db') as db:Operations.commit(db,'one',{'committed':'new'})
        self.assertEqual(self.ops.cancel('one')['state'],'COMMITTED')
        self.assertFalse(self.ops.admit(self.body)[1])
    def test_cancelled_before_execution_never_starts(self):
        self.ops.admit(self.body);self.ops.cancel('one');self.assertFalse(self.ops.begin('one'));self.assertEqual(self.ops.get('one')['state'],'CANCELLED')
    def test_failed_cancel_write_does_not_acknowledge(self):
        self.ops.admit(self.body)
        with sqlite3.connect(self.root/'journal.db') as db:db.execute("CREATE TRIGGER deny_cancel BEFORE UPDATE ON requests BEGIN SELECT RAISE(ABORT,'injected'); END")
        with self.assertRaises(sqlite3.IntegrityError):self.ops.cancel('one')
        self.assertEqual(self.ops.get('one')['state'],'ACCEPTED')

    def test_full_history_retains_deduplication(self):
        for i in range(64):
            body={**self.body,'request_id':'item-'+str(i)}
            self.ops.admit(body);self.ops.begin(body['request_id']);self.ops.finish(body['request_id'],'FAILED',{})
        self.assertFalse(self.ops.admit({**self.body,'request_id':'item-0'})[1])
        with self.assertRaisesRegex(Rejected,'history_full'):self.ops.admit(self.body)

class ConcurrentBoundary(unittest.TestCase):
    setUp=DurableContracts.setUp
    tearDown=DurableContracts.tearDown
    def test_real_concurrent_cancel_and_commit(self):
        import threading
        for i in range(20):
            identity='race-'+str(i);body={**self.body,'request_id':identity};self.ops.admit(body);self.ops.begin(identity)
            with sqlite3.connect(self.root/'journal.db') as db:before=db.execute('SELECT data FROM state').fetchone()
            barrier=threading.Barrier(2);answers={};errors=[]
            def commit():
                try:
                    barrier.wait()
                    with sqlite3.connect(self.root/'journal.db',timeout=.5) as db:
                        try:Operations.commit(db,identity,{'committed':identity});answers['commit']='won'
                        except Cancelled:db.rollback();answers['commit']='cancelled'
                except Exception as error:errors.append(error)
            def cancel():
                try:barrier.wait();answers['cancel']=self.ops.cancel(identity)['state']
                except Exception as error:errors.append(error)
            threads=[threading.Thread(target=commit),threading.Thread(target=cancel)]
            for thread in threads:thread.start()
            for thread in threads:thread.join(3);self.assertFalse(thread.is_alive())
            self.assertEqual(errors,[])
            state=self.ops.get(identity)['state']
            with sqlite3.connect(self.root/'journal.db') as db:after=db.execute('SELECT data FROM state').fetchone()
            if state=='COMMITTED':
                self.assertEqual(answers,{'commit':'won','cancel':'COMMITTED'});self.assertEqual(json.loads(after[0]),{'committed':identity})
            else:
                self.assertEqual(state,'CANCEL_REQUESTED');self.assertEqual(answers,{'commit':'cancelled','cancel':'CANCEL_REQUESTED'});self.assertEqual(after,before)
                self.ops.finish(identity,'CANCELLED',{})
