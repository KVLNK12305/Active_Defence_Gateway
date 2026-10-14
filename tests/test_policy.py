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

    def test_risk_79_does_not_escalate(self):
        self.assertEqual(self.engine.evaluate(100, 79), Action.ALLOW)

    def test_risk_80_escalates_allow_to_mirror(self):
        self.assertEqual(self.engine.evaluate(100, 80), Action.MIRROR)
        self.assertEqual(self.engine.evaluate(70, 100), Action.MIRROR)

    def test_risk_never_weakens_drop(self):
        # Regression: risk >= 80 used to turn DROP-range trust into MIRROR.
        self.assertEqual(self.engine.evaluate(39, 100), Action.DROP)
        self.assertEqual(self.engine.evaluate(0, 80), Action.DROP)

    def test_risk_keeps_mirror(self):
        self.assertEqual(self.engine.evaluate(40, 100), Action.MIRROR)

    def test_precedence_grid_all_boundaries(self):
        # Every trust boundary x every risk boundary, against the explicit precedence table.
        A, M, D = Action.ALLOW, Action.MIRROR, Action.DROP
        risks = (0, 79, 80, 100)
        table = {
            100: (A, A, M, M),
            90:  (A, A, M, M),
            89:  (A, A, M, M),
            70:  (A, A, M, M),
            69:  (M, M, M, M),
            40:  (M, M, M, M),
            39:  (D, D, D, D),
            0:   (D, D, D, D),
        }
        for trust, row in table.items():
            for risk, expected in zip(risks, row):
                with self.subTest(trust=trust, risk=risk):
                    self.assertEqual(self.engine.evaluate(trust, risk), expected)

    def test_risk_threshold_constant(self):
        self.assertEqual(PolicyConfig.RISK_MIRROR, 80)

if __name__ == '__main__':
    unittest.main()
