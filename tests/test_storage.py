import contextlib,errno,json,os,sqlite3,tempfile,unittest
from pathlib import Path
from certweft.operations import Operations,StorageBlocked
from certweft.core import Writer
from certweft import storage

class StorageSafety(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.ops=Operations(self.root);self.ops.initialize()
        self.body={'op':'submit','request_id':'one','certificate':'pem','epoch':'epoch','revision':1}
        with contextlib.closing(sqlite3.connect(self.root/'journal.db')) as db, db:
            db.execute('CREATE TABLE state(id INTEGER PRIMARY KEY,data TEXT)');db.execute('INSERT INTO state VALUES(1,?)',(json.dumps({'committed':'old'}),));db.execute('CREATE TABLE pressure(data BLOB)')
    def tearDown(self):self.temp.cleanup()
    def quota(self,event):
        with contextlib.closing(sqlite3.connect(self.root/'journal.db')) as db, db:
            db.execute('CREATE TRIGGER pressure '+event+' BEGIN INSERT INTO pressure VALUES(zeroblob(65536)); END')
            maximum=db.execute('PRAGMA page_count').fetchone()[0]+1
        return Operations(self.root,maximum)
    def test_pager_full_commit_preserves_both_rows(self):
        self.ops.admit(self.body);self.ops.begin('one');ops=self.quota("BEFORE UPDATE ON requests WHEN NEW.state='COMMITTED'")
        db=sqlite3.connect(self.root/'journal.db');db.execute('PRAGMA max_page_count='+str(ops.max_pages))
        try:
            with self.assertRaises(sqlite3.OperationalError) as result:Operations.commit(db,'one',{'committed':'new'})
            self.assertEqual(result.exception.sqlite_errorname,'SQLITE_FULL');db.rollback()
            self.assertEqual(json.loads(db.execute('SELECT data FROM state').fetchone()[0]),{'committed':'old'})
            self.assertEqual(self.ops.get('one')['state'],'RUNNING')
        finally:db.close()
    def test_full_cancel_is_not_persisted_and_blocks_later_commit(self):
        self.ops.admit(self.body);self.ops.begin('one');ops=self.quota("BEFORE UPDATE ON requests WHEN NEW.state='CANCEL_REQUESTED'")
        with self.assertRaises(sqlite3.OperationalError) as result:ops.cancel('one')
        self.assertEqual(result.exception.sqlite_errorname,'SQLITE_FULL');ops.latch_storage(result.exception)
        self.assertEqual(ops.get('one')['state'],'RUNNING')
        with contextlib.closing(sqlite3.connect(self.root/'journal.db')) as db, db:
            with self.assertRaises(StorageBlocked):Operations.commit(db,'one',{'committed':'new'})
    def test_storage_latch_survives_reopen_but_allows_required_recovery(self):
        self.ops.admit(self.body);self.ops.begin('one');self.ops.latch_storage(OSError(errno.ENOSPC,'full'))
        reopened=Operations(self.root)
        with self.assertRaisesRegex(StorageBlocked,'storage_unavailable'):reopened.admit({**self.body,'request_id':'two'})
        self.assertFalse(reopened.admit(self.body)[1])
        record=reopened.recovery_budget('one');self.assertEqual(record,reopened.recovery_budget('one'))
        self.assertEqual(record['seconds'],5)
    def test_storage_classification_does_not_latch_ordinary_constraint(self):
        self.assertFalse(storage.failed({'sqlite_error':'SQLITE_CONSTRAINT_TRIGGER'}))
        self.assertTrue(storage.failed({'sqlite_error':'SQLITE_READONLY_DBMOVED'}))
        self.assertTrue(storage.failed(OSError(errno.EROFS,'readonly')))
    def test_writer_closes_connection_without_garbage_collection(self):
        import gc
        writer=Writer(self.root,'unused','unused','unused','unused','localhost','127.0.0.1',1)
        gc.disable()
        try:
            for _ in range(20):
                with writer.locked() as (db,_):db.execute('SELECT 1')
            with self.assertRaises(sqlite3.ProgrammingError):db.execute('SELECT 1')
            for entry in Path('/proc/self/fd').iterdir():
                try:target=os.readlink(entry)
                except FileNotFoundError:continue
                self.assertNotEqual(target,str(self.root/'journal.db'))
        finally:gc.enable()
