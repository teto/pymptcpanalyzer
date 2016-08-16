from unittest import TestCase
import unittest

import mptcpanalyzer as mp
from mptcpanalyzer.cli import MpTcpAnalyzer
from mptcpanalyzer.config import MpTcpAnalyzerConfig
import mptcpanalyzer.data as core
import mptcpanalyzer.plots as plots
import pandas as pd
from stevedore.extension import Extension


mptcp_pcap = "examples/iperf-mptcp-0-0.pcap"



# https://github.com/openstack/stevedore/blob/master/stevedore/tests/test_test_manager.py
# TODO use make_test_instance and pass directly instances 
"""

"""
class IntegrationTest(TestCase):
    """
    Few reminders :
        :w @unittest.expectedFailure

    TODO how to test the options --title ? --skip_subflow ?
    """
    def setUp(self):

        config = MpTcpAnalyzerConfig()

        self.m = MpTcpAnalyzer(config)
        self.m.cmd_mgr.make_test_instance("placeholder", None, None, None)
        # self.assertTrue

    def load_all_plugins(self):
        """
        We have to load them manually
        """
        mgr = self.m.plot_mgr.make_test_instance(
        #name , entry point, plugin, obj
                [ Extension("attr", 'mptcpanalyzer.plots.dsn:PerSubflowTimeVsX',
# pkg_resources.
# entry_points.load
                    None
                    , 
                    mp.plots.dsn.PerSubflowTimeVsX()
                    ) ]
                )


    def test_loadconfig(self):
        """
        Override XDG_CONFIG_HOME and checks it's correctly loaded
        """
        pass

    def test_oneshot(self):
        # TODO test when launched via subprocess 
        # - with a list of commands passed via stdin
        pass

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
        # Test the --batch flag
        # subprocess.Popen()
        pass 

    def test_config(self):
        """
        Reads a config file and make sure some default values are ok
        """

        # config = MpTcpAnalyzerConfig()
        cfg = MpTcpAnalyzerConfig("tests/test_config.ini")
        self.assertEqual(cfg["DEFAULT"]["tshark_binary"], "fake_tshark")
        self.assertEqual(cfg["DEFAULT"]["delimiter"], "|")

    @unittest.skip("Not sure pcap are valid yet")
    def test_mapping_connections(self):
        """
        Test to check if the program correctly mapped one connection to another
        """
        # expects 2 datasets
        # load from csv
        ds1 = self.m.load_into_pandas("examples/node0.pcap")
        ds2 = self.m.load_into_pandas("examples/node1.pcap")
        ds1 = ds1[(ds1.mptcpstream == args.mptcp_client_id)]
                
        ds2 = ds2[ds2.mptcpstream == args.mptcp_server_id]
        # core.map_subflows_between_2_datasets ()

        self.m.do_plot("plot owd 0")

    def test_load(self):
        """
        Check that it can load a basic mptcp pcap
        """
        # to test for errors
        # with self.assertRaises(ValueError):
        self.m.do_load("examples/iperf-mptcp-0-0.pcap --regen")

    def test_list_subflows(self):
        """
        Test that it can list subflows
        """
        # self.m.do_ls("0")
        # self.m.do_load("examples/iperf-mptcp-0-0.pcap")
        self.m.do_ls("0")
        self.m.do_ls("-1")

    def test_list_connections(self):
        """
        TODO should return different number
        """
        self.m.do_lc("0")
        self.m.do_lc("-1")

    def test_list_plots_attr(self):
        """
        Check if properly list available plugins
        """
#http://docs.openstack.org/developer/stevedore/managers.html#stevedore.extension.Extension
# plugin, obj
        # load_all_plugins
        self.load_all_plugins()
        plot_names = self.m._list_available_plots()
        self.assertIn("attr", plot_names)
        # self.assertIn("", plot_names)

    def test_plot_attr_preloaded(self):
        """
        Loads the dataset first 
        """
        self.load_all_plugins()
        self.m.do_load("examples/iperf-mptcp-0-0.pcap")
        self.m.do_plot("attr 0 Client dsn")

    def test_plot_attr_postloaded(self):
        self.load_all_plugins()
        # self.m.do_load("examples/iperf-mptcp-0-0.pcap")
        self.m.do_plot("attr examples/iperf-mptcp-0-0.pcap 0 Client dsn")


    def test_list_plots_2(self):
        plot_names = self.m._list_available_plots()
        # self.assertIn("attr", plot_names)
        # self.assertIn("", plot_names)

    def test_generate_plots(self):
        """
        """
        self.m.do_load("examples/iperf-mptcp-0-0.pcap")
        # TODO precise file
        self.m.do_plot("plot dsn 0")
        self.m.do_plot("plot interarrival 0")

        # TODO 

    def test_generate_plot_ns3(self):
        """
        Not a good test, too involving
        """

        self.m.do_plot("plot ns3 --meta examples/ cwnd 0")

