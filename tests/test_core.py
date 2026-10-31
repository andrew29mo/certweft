import tempfile,unittest
from pathlib import Path
from certweft.core import Writer,Rejected
from certweft.ca import reissue

class Contracts(unittest.TestCase):
    def test_writer_excludes_second_writer(self):
        with tempfile.TemporaryDirectory() as t:
            w=Writer(t,'nginx','conf','ca','key','localhost','127.0.0.1',443)
            with w.locked():
                with self.assertRaises(BlockingIOError):
                    with w.locked():pass
    def test_uninitialized_cannot_recover(self):
        with tempfile.TemporaryDirectory() as t:
            w=Writer(t,'nginx','conf','ca','key','localhost','127.0.0.1',443)
            with self.assertRaises(Rejected):w.recover()
    def test_ca_output_never_overwritten(self):
        with tempfile.TemporaryDirectory() as t:
            out=Path(t)/'cert';out.write_bytes(b'preserve')
            with self.assertRaises(Rejected):reissue('missing','url','root','key','password',out)
            self.assertEqual(out.read_bytes(),b'preserve')
if __name__=='__main__':unittest.main()

class WireNegative(unittest.TestCase):
    def test_incomplete_http_header_rejected(self):
        from unittest.mock import patch,MagicMock
        import hashlib
        from certweft.core import probe
        tls=MagicMock();tls.__enter__.return_value=tls
        tls.session_reused=False;tls.getpeercert.return_value=b'leaf'
        tls.recv.side_effect=[b'HTTP/1.1 200 OK\r\n',b'']
        context=MagicMock();context.wrap_socket.return_value=tls
        with patch('certweft.core.ssl.SSLContext',return_value=context),patch('certweft.core.socket.create_connection'):
            with self.assertRaises(Rejected):
                probe('127.0.0.1',443,'localhost','root',hashlib.sha256(b'leaf').hexdigest())

class CommitFailure(unittest.TestCase):
    def test_real_busy_commit_discards_uncommitted_state(self):
        import sqlite3,json
        with tempfile.TemporaryDirectory() as t:
            w=Writer(t,'nginx','conf','ca','key','localhost','127.0.0.1',443)
            with w.locked() as (db,_):
                w.save(db,{'committed':'old'})
                with sqlite3.connect(Path(t)/'journal.db') as reader:
                    reader.execute('BEGIN')
                    reader.execute('SELECT data FROM state').fetchone()
                    with self.assertRaises(sqlite3.OperationalError):w.save(db,{'committed':'new'})
                    self.assertFalse(db.in_transaction)
                    self.assertEqual(json.loads(db.execute('SELECT data FROM state').fetchone()[0]),{'committed':'old'})

class CurvePolicy(unittest.TestCase):
    def test_subject_text_cannot_spoof_curve(self):
        from certweft.core import run,validate
        with tempfile.TemporaryDirectory() as t:
            key=Path(t)/'key';cert=Path(t)/'cert'
            run(['openssl','ecparam','-name','secp384r1','-genkey','-noout','-out',key])
            run(['openssl','req','-new','-x509','-key',key,'-sha256','-subj','/CN=ASN1 OID: prime256v1',
                 '-addext','subjectAltName=DNS:localhost','-addext','basicConstraints=critical,CA:FALSE',
                 '-addext','extendedKeyUsage=serverAuth','-out',cert])
            with self.assertRaisesRegex(Rejected,'algorithm_policy'):validate(cert,key,cert,'localhost')
