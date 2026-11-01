"""Real process-group cleanup, including an exited leader and held lease/pipes."""
import fcntl,os,pathlib,signal,subprocess,sys,tempfile,time,unittest
from certweft.service import reap_executor

@unittest.skipUnless(sys.platform=='linux','Linux lease/process qualification')
class ExecutorGroup(unittest.TestCase):
    def test_exited_leader_does_not_skip_pipe_and_lease_holding_descendant(self):
        with tempfile.TemporaryDirectory() as folder:
            path=pathlib.Path(folder)/'lease';fd=os.open(path,os.O_CREAT|os.O_RDWR,0o600);fcntl.flock(fd,fcntl.LOCK_EX)
            leader=None;probe=None;descendant=None
            def alive(pid):
                try:return pathlib.Path('/proc',str(pid),'stat').read_text().split()[2]!='Z'
                except (FileNotFoundError,ProcessLookupError):return False
            try:
                script="import subprocess,sys; p=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)'],close_fds=False); print(p.pid,flush=True)"
                leader=subprocess.Popen([sys.executable,'-c',script],pass_fds=(fd,),start_new_session=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                descendant=int(leader.stdout.readline());leader.wait(timeout=3);self.assertEqual(leader.returncode,0)
                os.close(fd);fd=None;probe=os.open(path,os.O_RDWR)
                with self.assertRaises(BlockingIOError):fcntl.flock(probe,fcntl.LOCK_EX|fcntl.LOCK_NB)
                self.assertTrue(alive(descendant))
                with self.assertRaises(subprocess.TimeoutExpired):leader.communicate(timeout=.05)
                reap_executor(leader,True)
                until=time.monotonic()+3
                while alive(descendant) and time.monotonic()<until:time.sleep(.01)
                self.assertFalse(alive(descendant),'descendant_survived_group_reap')
                fcntl.flock(probe,fcntl.LOCK_EX|fcntl.LOCK_NB)
            finally:
                if leader is not None:
                    # Independent fallback cleanup must also work when the
                    # production reap function is deliberately mutated/broken.
                    try:os.killpg(leader.pid,signal.SIGKILL)
                    except ProcessLookupError:pass
                    reap_executor(leader,False)
                    until=time.monotonic()+3
                    while descendant is not None and alive(descendant) and time.monotonic()<until:time.sleep(.01)
                    if descendant is not None and alive(descendant):raise AssertionError('descendant_test_cleanup_failed')
                if fd is not None:os.close(fd)
                if probe is not None:os.close(probe)
