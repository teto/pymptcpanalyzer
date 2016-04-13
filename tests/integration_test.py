from unittest import TestCase

from mptcpanalyzer.cli import MpTcpAnalyzer
from mptcpanalyzer.config import MpTcpAnalyzerConfig




class IntegrationTest(TestCase):
    """
    Few reminders :
        :w @unittest.expectedFailure
    """
    def setUp(self):

        config = MpTcpAnalyzerConfig()

        self.m = MpTcpAnalyzer (config)
        # self.assertTrue

    def test_oneshot(self):
        # TODO test when launched via subprocess 
        # - with a list of commands passed via stdin
        pass

    def test_batch(self):
        # Test the --batch flag
        # subprocess.Popen()
        pass 

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
        # self.m.do_ls("0")
        # self.m.do_load("examples/iperf-mptcp-0-0.pcap")
        self.m.do_ls("0")
        self.m.do_ls("-1")

    def test_list_connections(self):
        self.m.do_lc("0")
        self.m.do_lc("-1")

    def test_list_plots(self):
        plot_names = self.m._list_available_plots()
        self.assertIn("dsn", plot_names)
        # self.assertIn("", plot_names)
        pass

    def test_generate_plots(self):
        self.m.do_load("examples/iperf-mptcp-0-0.pcap")
        # TODO precise file
        self.m.do_plot("plot dsn 0")

    # def test_plot_dsn(self):
    #     self.m.do_plot("plot dsn 0")

