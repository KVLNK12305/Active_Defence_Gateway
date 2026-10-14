import unittest
import sys
import os

# Add controller dir to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../controller')))

from policy import Action, PolicyEngine, PolicyConfig

class TestPolicyEngine(unittest.TestCase):
    def setUp(self):
        self.engine = PolicyEngine()

    def test_trust_100(self):
        self.assertEqual(self.engine.evaluate(100), Action.ALLOW)

    def test_trust_95(self):
        self.assertEqual(self.engine.evaluate(95), Action.ALLOW)

    def test_trust_90(self):
        self.assertEqual(self.engine.evaluate(90), Action.ALLOW)

    def test_trust_89(self):
        self.assertEqual(self.engine.evaluate(89), Action.ALLOW)

    def test_trust_70(self):
        self.assertEqual(self.engine.evaluate(70), Action.ALLOW)

    def test_trust_69(self):
        self.assertEqual(self.engine.evaluate(69), Action.MIRROR)

    def test_trust_40(self):
        self.assertEqual(self.engine.evaluate(40), Action.MIRROR)

    def test_trust_39(self):
        self.assertEqual(self.engine.evaluate(39), Action.DROP)

    def test_trust_20(self):
        self.assertEqual(self.engine.evaluate(20), Action.DROP)

    def test_trust_19(self):
        self.assertEqual(self.engine.evaluate(19), Action.DROP)

    def test_trust_0(self):
        self.assertEqual(self.engine.evaluate(0), Action.DROP)

if __name__ == '__main__':
    unittest.main()
