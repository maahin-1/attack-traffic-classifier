import unittest
import numpy as np
from attack_traffic.shift_audit import Summary, _outside_fraction


class ShiftSummaryTests(unittest.TestCase):
    def test_exact_counts_and_bounded_deterministic_sample(self):
        data = np.zeros((100, 27))
        data[:, 0] = np.arange(100) - 2
        left, right = Summary(capacity=7), Summary(capacity=7)
        for item in (left, right):
            item.add(data[:40])
            item.add(data[40:])
        self.assertEqual(left.export(), right.export())
        value = left.export()
        self.assertEqual(value['reservoir_rows'], 7)
        f = value['features']['flow_duration']
        self.assertEqual(f['minimum'], -2)
        self.assertEqual(f['maximum'], 97)
        self.assertEqual(f['negative_count'], 2)
        self.assertEqual(f['zero_fraction'], .01)
        self.assertEqual(f['mean'], 47.5)

    def test_invalid_and_empty(self):
        s = Summary()
        self.assertEqual(s.export()['rows'], 0)
        with self.assertRaises(ValueError):
            s.add(np.full((1, 27), np.nan))

    def test_absent_external_class_has_null_fraction(self):
        self.assertIsNone(_outside_fraction(0, 0))
        self.assertEqual(_outside_fraction(0, 5), 0.0)
        self.assertEqual(_outside_fraction(2, 5), .4)
