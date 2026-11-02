"""Installed launcher and client invariants; real systemd/CA evidence is in VM."""
import json,os,pathlib,sys,tempfile,unittest
from unittest.mock import patch
from certweft.core import Rejected
from certweft.cli import recover
from certweft.deployment import master_identity,unit_identity

class RecoveryClient(unittest.TestCase):
    def test_terminal_history_cannot_claim_live_permission(self):
        kinds={'cert':('recover-certificate','VERIFIED_CLOSED'),'journal':('reconcile-closed','JOURNAL_VERIFIED_CLOSED'),'intent':('prepare-opening','OPENING_VERIFIED_CLOSED'),'release':('prepare-release','RELEASE_VERIFIED_CLOSED'),'open':('open-updates','OPENED')};seen=[]
        def call(endpoint,body):
            seen.append(body)
            if body['op']=='recovery-status':return {'gate':{'state':'VERIFIED_CLOSED'},'gate_allows_updates':False,'executor_busy':False}
            self.assertEqual(body['op'],'recovery-request-status');suffix=body['request_id'].split('-')[-1];kind,state=kinds[suffix]
            return {'result':{'request_id':body['request_id'],'kind':kind,'state':state}}
        with patch('certweft.cli.os.geteuid',return_value=0),patch('certweft.cli.call',side_effect=call):
            with self.assertRaisesRegex(Rejected,'historical_completion_not_current_permission'):recover('unused','trial',10)
        self.assertTrue(all(b['op'] in {'recovery-status','recovery-request-status'} for b in seen))
    def test_failed_existing_step_is_never_resubmitted(self):
        seen=[]
        def call(endpoint,body):
            seen.append(body)
            if body['op']=='recovery-status':return {'gate':{'state':'VERIFY_REQUIRED'},'executor_busy':False}
            return {'result':{'request_id':'trial-cert','kind':'recover-certificate','state':'EXPIRED'}}
        with patch('certweft.cli.os.geteuid',return_value=0),patch('certweft.cli.call',side_effect=call):
            with self.assertRaisesRegex(Rejected,'recovery_step_EXPIRED'):recover('unused','trial',10)
        self.assertFalse(any(b['op']=='recover-certificate' for b in seen))
    def test_non_root_recovery_refused_before_connection(self):
        with patch('certweft.cli.os.geteuid',return_value=123),patch('certweft.cli.call') as transport:
            with self.assertRaisesRegex(Rejected,'admin_required'):recover('unused','trial',10)
            transport.assert_not_called()

@unittest.skipUnless(sys.platform=='linux' and os.geteuid()==0,'Linux root launcher identity')
class MasterBinding(unittest.TestCase):
    def test_live_pid_binary_identity_and_malformed_pid(self):
        # Root-private /var/tmp hierarchy matches deployment ownership checks.
        with tempfile.TemporaryDirectory(dir='/var/tmp') as folder:
            p=pathlib.Path(folder)/'pid';p.write_text(str(os.getpid())+'\n');p.chmod(0o600)
            identity=master_identity(p,sys.executable);self.assertEqual(identity['pid'],os.getpid());self.assertTrue(identity['start'].isdigit())
            with self.assertRaisesRegex(Rejected,'master_binary'):master_identity(p,'/bin/false')
            p.write_text('1\n2\n')
            with self.assertRaisesRegex(Rejected,'master_pid_file'):master_identity(p,sys.executable)
    def test_symlink_pid_file_not_followed(self):
        with tempfile.TemporaryDirectory(dir='/var/tmp') as folder:
            target=pathlib.Path(folder)/'target';target.write_text(str(os.getpid()));link=pathlib.Path(folder)/'pid';link.symlink_to(target)
            with self.assertRaises(OSError):master_identity(link,sys.executable)

class FixedDeploymentPolicy(unittest.TestCase):
    def test_installed_ca_policy_matches_reviewed_source(self):
        import importlib.resources
        source=pathlib.Path(__file__).resolve().parents[1]/'policy/server.tpl'
        self.assertEqual((importlib.resources.files('certweft')/'assets/server.tpl').read_bytes(),source.read_bytes())
    def test_unrelated_unit_selector_rejected_without_manager_call(self):
        with patch('certweft.core.run') as command:
            with self.assertRaisesRegex(Rejected,'fixed_master_unit'):unit_identity('nginx.service','/usr/sbin/nginx')
            command.assert_not_called()
