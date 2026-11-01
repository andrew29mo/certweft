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

class CredentialBoundary(unittest.TestCase):
    def test_missing_systemd_credential_rejected(self):
        from unittest.mock import patch
        from certweft.ca import reissue_credential
        with patch.dict('os.environ',{},clear=True):
            with self.assertRaisesRegex(Rejected,'credential_missing'):
                reissue_credential('step','url','root','key','out')
    def test_public_credential_rejected_before_signing(self):
        from unittest.mock import patch
        from certweft.ca import reissue_credential
        with tempfile.TemporaryDirectory() as t:
            f=Path(t)/'provisioner-password';f.write_text('private-test-only');f.chmod(0o644)
            with patch.dict('os.environ',{'CREDENTIALS_DIRECTORY':t}),patch('certweft.ca.reissue') as sign:
                with self.assertRaisesRegex(Rejected,'credential_permissions'):
                    reissue_credential('step','url','root','key','out')
                sign.assert_not_called()

class SecretOutput(unittest.TestCase):
    def test_stderr_only_secret_is_rejected(self):
        from tools.policy_vm import check_outputs
        with self.assertRaisesRegex(AssertionError,'secret_output'):
            check_outputs('sentinel',b'clean',b'error sentinel')
        check_outputs('sentinel',b'clean',b'clean')

class ExecutorContract(unittest.TestCase):
    def test_management_api_rejects_extra_paths_and_commands(self):
        from certweft.executor import dispatch
        config={'controller_uid':123}
        for body in [{'op':'shell','command':'id'}, {'op':'activate','path':'/etc/passwd'}, {'op':'status','root':'/'}]:
            with self.assertRaisesRegex(Rejected,'request_shape'):dispatch(config,body,123)
    def test_controller_cannot_request_admin_recovery(self):
        from certweft.executor import dispatch
        with self.assertRaisesRegex(Rejected,'admin_required'):
            dispatch({'controller_uid':123},{'op':'recover'},123)
    def test_unconfigured_peer_rejected(self):
        from certweft.executor import dispatch
        with self.assertRaisesRegex(Rejected,'peer_denied'):
            dispatch({'controller_uid':123},{'op':'status'},456)
