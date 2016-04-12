from unittest import TestCase

from mptcpanalyzer.cli import MpTcpAnalyzer
from mptcpanalyzer.config import MpTcpAnalyzerConfig

class IntegrationTest(TestCase):

    def setUp(self):

        config = MpTcpAnalyzerConfig()

        self.m = MpTcpAnalyzer (config)
        # self.assertTrue

    def test_config(self):

        # config = MpTcpAnalyzerConfig()
        cfg = MpTcpAnalyzerConfig("tests/test_config.ini")
        self.assertEqual(cfg["DEFAULT"]["tshark_binary"], "fake_tshark")

    def test_mapping(self):
        # expects 2 datasets
        # self._map_subflows_between_2_datasets ()
        pass

    def test_load(self):
        # to test for errors
        # with self.assertRaises(ValueError):
        self.m.do_load("examples/iperf-mptcp-0-0.pcap --regen")

    def test_list_subflows(self):
        self.m.do_ls("0")
        self.m.do_ls("-1")

    def test_list_connections(self):
        self.m.do_lc("0")
        self.m.do_lc("-1")

    def test_list_plots(self):
        # self.m._list_available_plots()
        pass

    def test_plot_dsn(self):
        self.m.do_plot("0")
