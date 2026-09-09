"""
Runs every module's `_self_check()` under one command: `python -m unittest discover`.
Assertion logic stays in each module (single source of truth); this just
aggregates them so a regression in any one module fails the whole suite
instead of requiring `python -m wasp.<module>` per file.
"""

import unittest

from wasp import blackboard, probe, network_scan


class SelfChecks(unittest.TestCase):
    def test_blackboard(self):
        blackboard._self_check()

    def test_probe(self):
        probe._self_check()

    def test_network_scan(self):
        network_scan._self_check()


if __name__ == "__main__":
    unittest.main()
