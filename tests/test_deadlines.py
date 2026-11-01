import json,sqlite3,sys,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch
from certweft import deadlines
from certweft.core import run,Rejected
from certweft.operations import Operations
class BudgetContracts(unittest.TestCase):
    def test_expired_commit_changes_neither_state_nor_request(self):
        with tempfile.TemporaryDirectory() as t:
            ops=Operations(Path(t));ops.initialize();body={'op':'submit','request_id':'id','certificate':'pem','epoch':'epoch','revision':1,'timeout_seconds':1}
            ops.admit(body);ops.begin('id')
            with sqlite3.connect(ops.path) as db:
                db.execute('CREATE TABLE state(id INTEGER PRIMARY KEY,data TEXT)')
                timing=ops.get('id')['timing'];timing['activation']['expires_boot_ns']=deadlines.now_ns()-1
                db.execute('UPDATE requests SET timing=?',(json.dumps(timing),));db.commit()
                with self.assertRaises(deadlines.Expired):Operations.commit(db,'id',{'committed':'candidate'})
                db.rollback();self.assertIsNone(db.execute('SELECT * FROM state').fetchone())
            self.assertEqual(ops.get('id')['state'],'RUNNING')
    def test_replay_and_recovery_budget_not_reset(self):
        with tempfile.TemporaryDirectory() as t:
            ops=Operations(Path(t));ops.initialize();body={'op':'submit','request_id':'id','certificate':'pem','epoch':'epoch','revision':1,'timeout_seconds':2}
            initial=ops.admit(body)[0]['timing'];self.assertEqual(ops.admit(body)[0]['timing'],initial)
            with self.assertRaisesRegex(Rejected,'request_conflict'):ops.admit({**body,'timeout_seconds':3})
            first=ops.recovery_budget('id');self.assertEqual(Operations(Path(t)).recovery_budget('id'),first)
    def test_boot_change_and_wall_jump_rejected(self):
        record=deadlines.create(10)
        with patch('certweft.deadlines.boot_id',return_value='different'):
            with self.assertRaisesRegex(deadlines.Expired,'boot_changed'):deadlines.remaining(record)
        with patch('certweft.deadlines.time.time_ns',return_value=record['accepted_wall_ns']-10_000_000_000):
            with self.assertRaisesRegex(deadlines.Expired,'wall_clock_anomaly'):deadlines.remaining(record)
    def test_real_subprocess_uses_remaining_budget(self):
        record=deadlines.create(1);record['expires_boot_ns']=deadlines.now_ns()+50_000_000
        start=time.monotonic()
        with self.assertRaises(deadlines.Expired):
            with deadlines.use(record):run([sys.executable,'-c','import time;time.sleep(2)'])
        self.assertLess(time.monotonic()-start,1)

    def test_sql_write_delay_crosses_deadline_before_commit(self):
        with tempfile.TemporaryDirectory() as t:
            ops=Operations(Path(t));ops.initialize();body={'op':'submit','request_id':'late','certificate':'pem','epoch':'epoch','revision':1,'timeout_seconds':1}
            ops.admit(body);ops.begin('late')
            with sqlite3.connect(ops.path) as db:
                db.execute('CREATE TABLE state(id INTEGER PRIMARY KEY,data TEXT)')
                db.execute('INSERT INTO state VALUES(1,?)',(json.dumps({'committed':'old'}),));db.commit()
                timing=ops.get('late')['timing'];timing['activation']['expires_boot_ns']=deadlines.now_ns()+100_000_000
                db.execute('UPDATE requests SET timing=?',(json.dumps(timing),));db.commit()
                entered=[]
                def delay():
                    entered.append(deadlines.now_ns())
                    self.assertLess(entered[0],timing['activation']['expires_boot_ns'])
                    until=timing['activation']['expires_boot_ns']+20_000_000
                    while deadlines.now_ns()<until:time.sleep(.005)
                    return 0
                db.create_function('delay_commit',0,delay)
                db.execute("CREATE TRIGGER delayed BEFORE UPDATE ON requests WHEN NEW.state='COMMITTED' BEGIN SELECT delay_commit(); END")
                db.commit()
                self.assertGreater(deadlines.remaining(timing['activation']),0)
                with self.assertRaises(deadlines.Expired):Operations.commit(db,'late',{'committed':'candidate'})
                self.assertEqual(len(entered),1)
                db.rollback()
                self.assertEqual(json.loads(db.execute('SELECT data FROM state').fetchone()[0]),{'committed':'old'})
                self.assertEqual(ops.get('late')['state'],'RUNNING')
