
# from unittest import TestCase
# import unittest

# import mptcpanalyzer.analysis as ma


# class TestAnalysis(TestCase):
#     """
#     Few reminders :
#         :w @unittest.expectedFailure
#     """
#     def setUp(self):

#         self.m = ma.MpTcpNumerics()
#         # self.assertTrue
#         self.m.do_load("examples/topology.json")

#     def test_oneshot(self):
#         # TODO test when launched via subprocess 
#         # - with a list of commands passed via stdin
#         pass

#     def test_batch(self):
#         # Test the --batch flag
#         # subprocess.Popen()
#         pass 

#     def test_load(self):
#         # to test for errors
#         # with self.assertRaises(ValueError):
#         self.m.do_load("examples/topology.json")


#     @unittest.skip("Module not mature yet")
#     def test_cycle(self):
#         res = self.m._compute_cycle()
#         self.assertAlmostEqual(res, 20)
