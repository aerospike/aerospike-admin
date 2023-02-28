import unittest
from parameterized import parameterized

from lib.view import templates


class HelperTests(unittest.TestCase):
    @parameterized.expand(
        [
            ([0.5, 0.8, 0.3], [10, 15, 20], 0.511),
            ([0.5, 0.8, 0.3], [-1, 0, 1], 0),
        ],
    )
    def test_weighted_avg(self, weights, values, expected):
        assert round(templates.weighted_avg(weights, values), 3) == expected
