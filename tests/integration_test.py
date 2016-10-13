from unittest import TestCase
import unittest

import mptcpanalyzer as mp
from mptcpanalyzer.cli import MpTcpAnalyzer, main
from mptcpanalyzer.config import MpTcpAnalyzerConfig
import mptcpanalyzer.data as core
import mptcpanalyzer.plots as plots
import pandas as pd
from stevedore.extension import Extension
import tempfile
import shlex

mptcp_pcap = "examples/iperf-mptcp-0-0.pcap"




def test_main(arguments_to_parse: str):
    """
    Used in the testsuite
    """
    return main(shlex.split(arguments_to_parse))

# 
class IntegrationTest(TestCase):
    """
    Few reminders :
        :w @unittest.expectedFailure
    List of builtin exceptions
    https://docs.python.org/3/library/exceptions.html
    """
    def setUp(self):

        config = MpTcpAnalyzerConfig()
        self.m = MpTcpAnalyzer(config)

    # def preload_pcap(self, regen: bool =False):
    #     cmd = "examples/iperf-mptcp-0-0.pcap"
    #     if regen:
    #         cmd += " --regen"
    #     self.m.do_load(cmd)

    def setup_plot_mgr(self):
        """
        We have to load them manually

        .. see: https://github.com/openstack/stevedore/blob/master/stevedore/tests/test_test_manager.py
        """

        #name , entry point, plugin, obj
        plots = [
            Extension("attr", 'mptcpanalyzer.plots.dsn:PerSubflowTimeVsAttribute',
                None, mp.plots.dsn.PerSubflowTimeVsAttribute())
        ]
        mgr = self.m.plot_manager.make_test_instance(plots)
        self.m.plot_manager = mgr
        # TODO now we need to use that !


    def test_oneshot(self):
        # TODO test when launched via subprocess
        # - with a list of commands passed via stdin
        cmd = " help"
        test_main(cmd)
        # self.assertEqual(ret, 0)
        

    # def test_regen(self):
    #     """
    #     Test that with regen we update the file
    #     """
    #     dat = pd.DataFrame(columns=mp.get_fields("fullname"))
    #     prefix = "examples/node0.pcap"
    #     dat.to_csv( prefix + ".csv", sep=self.m.config["DEFAULT"]["delimiter"])
    #     # with fopen("examples/node0.csv", "r+"):
    #     self.assertEqual()

    def test_batch(self):
        """
        Run several commands written in a file and make sure
        some files are created
        """
        with tempfile.TemporaryDirectory() as dirname:
            cmd = " --load {f} --batch {cmd_file}".format(
                f=mptcp_pcap,
                cmd_file="tests/batch_commands.txt",
            )
            self.assertEqual(test_main(cmd), 0, "An error happened")
            # self.batch
            # TODO assert files are created etc...


    # @unittest.skip("Not sure pcap are valid yet")
    def test_mapping_connections(self):
        """
        Test to check if the program correctly mapped one connection to another
        """
        # expects 2 datasets
        # load from csv
        ds1 = self.m.load_into_pandas("examples/node0.pcap")
        ds2 = self.m.load_into_pandas("examples/node1.pcap")

        # just looking to map mptcp.stream 0
        results = core.mptcp_match_connection(ds1, ds2, [0])
        # self.assertEqual( len(cmd), 0, "An error happened")
        self.assertGreaterEqual(len(cmd), 1, "There must be at least one result")

    # def test_plot_owd(self):
        # self.m.do_plot("plot owd 0")

    def test_load_pcap(self):
        """
        Check that it can load a basic mptcp pcap, w/o regen
        check it takes into account the cache
        check it fails when file does not exist or is corrupted
        """
        # to test for errors
        # with self.assertRaises(ValueError):
        self.m.do_load("examples/iperf-mptcp-0-0.pcap --regen")


    @unittest.skip
    def testlist_subflows(self):
        """
        Test that it can list subflows
        """
        # self.m.do_ls("0")
        # fails because the file is not loaded yet
        with self.assertRaises(mp.MpTcpException):
            self.m.do_ls("0")

        # self.preload_pcap()
        self.m.do_ls("0")

        # fails because there are no packets with this id
        with self.assertRaises(mp.MpTcpException):
            self.m.do_ls("4")

    def test_list_connections(self):
        """
        TODO should return different number
        """
        # fails because file not loaded
        self.assertRaises(mp.MpTcpException, self.m.do_lc, "")
        self.preload_pcap()
        self.m.do_lc("")

    def test_list_plots_attr(self):
        """
        Check if properly list available plugins
        """
        #http://docs.openstack.org/developer/stevedore/managers.html#stevedore.extension.Extension
        # plugin, obj
        # setup_plot_mgr
        self.setup_plot_mgr()
        plot_names = self.m.list_available_plots()
        print("plot names=", plot_names)
        self.assertIn("attr", plot_names)
        # self.assertIn("", plot_names)
        # for i in range():
        #     with self.subTest(i=i):
        #         self.assertIn()

    def test_plot_attr_preloaded(self):
        """
        Loads the dataset first
        """
        self.setup_plot_mgr()
        self.m.do_load("examples/iperf-mptcp-0-0.pcap")
        self.m.do_plot("attr 0 Client dsn")

    def test_plot_attr_postloaded(self):
        self.setup_plot_mgr()
        self.m.do_plot("attr examples/iperf-mptcp-0-0.pcap 0 Client dsn")
        # TODO test --title
        # self.m.do_plot("attr examples/iperf-mptcp-0-0.pcap 0 Client dsn")


    def test_list_plots_2(self):
        plot_names = self.m.list_available_plots()
        print("plot names=", plot_names)
        # self.assertIn("attr", plot_names)
        # self.assertIn("", plot_names)

    def testplots(self):
        """
        """
        self.preload_pcap()
        # TODO precise file
        # self.m.do_plot("attr 0")
        # self.m.do_plot("interarrival 0")

        # TODO


    @unittest.skip("not upstreamed yet")
    def testplot_ns3(self):
        """
        Not a good test, too involving
        """

        # self.m.do_plot("ns3 --meta examples/ cwnd 0")

