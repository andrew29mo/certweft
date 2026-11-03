"""Counterexamples for the resource evaluator; formal VM cases supply observations."""
import copy,pathlib,tempfile,unittest
from certweft.core import Writer,Rejected
from tools.closeout_vm import resource_checks

class CloseoutChecks(unittest.TestCase):
    def samples(self):
        return [{'elapsed_seconds':180+i*10,'writer':{'rss_kib':22000,'fds':6,'cgroup_pids':[10],'nrestarts':0},'nginx':{'cgroup_rss_kib':12000,'cgroup_fds':14,'cgroup_pids':[20,21],'cgroup_samples':[{},{}],'nrestarts':0},'disk':{'bytes':100}} for i in range(103)]
    def test_fixed_resources_pass(self):self.assertEqual(resource_checks(self.samples())['stable_samples'],103)
    def test_restart_or_residual_executor_cannot_mask_growth(self):
        for field,value in [('nrestarts',1),('cgroup_pids',[10,11])]:
            s=self.samples();s[-1]['writer'][field]=value
            with self.assertRaisesRegex(AssertionError,'writer_process_leak_or_restart'):resource_checks(s)
    def test_rss_trend_fd_disk_and_nginx_growth_fail(self):
        for kind in ['rss','fd','disk','nginx']:
            s=self.samples()
            for i,row in enumerate(s):
                if kind=='rss':row['writer']['rss_kib']+=i*20
                elif kind=='fd':row['writer']['fds']+=i//10
                elif kind=='disk':row['disk']['bytes']+=i
                else:row['nginx']['cgroup_pids'].append(99)
            with self.assertRaises(AssertionError):resource_checks(s)
    def test_generation_cap_is_actual_backend_rejection(self):
        with tempfile.TemporaryDirectory() as d:
            for i in range(16):(pathlib.Path(d)/('v-'+str(i))).mkdir()
            # stage reads candidate bytes then checks its formal generation limit,
            # before needing any key/config or creating a seventeenth directory.
            candidate=pathlib.Path(d)/'candidate';candidate.write_text('unused')
            w=Writer(d,'nginx','conf','ca','key','localhost','127.0.0.1',19443)
            with self.assertRaisesRegex(Rejected,'version_capacity'):w.stage(candidate)
            self.assertEqual(len(list(pathlib.Path(d).glob('v-*'))),16)
