import unittest,sys,os
sys.path.insert(0,os.path.join(os.path.dirname(__file__),"..","src"))
from pass_hash.core import NTLMAnalyzer,PTHDetector

class TestNTLM(unittest.TestCase):
    def test_parse(self):
        a=NTLMAnalyzer()
        r=a.parse_hash("admin:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0")
        self.assertEqual(r["user"],"admin")
        self.assertTrue(r["lm_disabled"])
    def test_generate(self):
        a=NTLMAnalyzer()
        h=a.generate_ntlm("password")
        self.assertEqual(len(h),32)
    def test_compare(self):
        a=NTLMAnalyzer()
        h=a.generate_ntlm("test")
        self.assertTrue(a.compare_hashes(h,h)["match"])

if __name__=="__main__": unittest.main()
