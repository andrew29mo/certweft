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
