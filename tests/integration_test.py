from unittest import TestCase
import unittest

import mptcpanalyzer as mp
from mptcpanalyzer.cli import MpTcpAnalyzer
from mptcpanalyzer.config import MpTcpAnalyzerConfig
import mptcpanalyzer.data as core
import mptcpanalyzer.plots as plots
from stevedore.extension import Extension

# https://github.com/openstack/stevedore/blob/master/stevedore/tests/test_test_manager.py
# TODO use make_test_instance and pass directly instances 
class IntegrationTest(TestCase):
    """
    Few reminders :
        :w @unittest.expectedFailure
    """
    def setUp(self):

        config = MpTcpAnalyzerConfig()

        self.m = MpTcpAnalyzer (config)
        self.m.cmd_mgr.make_test_instance("placeholder", None, None, None)
        # self.assertTrue

    def test_loadconfig(self):
        """
        Override XDG_CONFIG_HOME and checks it's correctly loaded
        """
        pass
    def test_oneshot(self):
        # TODO test when launched via subprocess 
        # - with a list of commands passed via stdin
        pass

    def test_regen(self):
        """
        Test that with regen we update the file
        """
        dat = pd.DataFrame(columns=mp.get_fields("fullname"))
        prefix = "examples/node0.pcap"
        dat.to_csv ( prefix + ".csv", sep=self.config["DEFAULT"]["separator"])
        # with fopen("examples/node0.csv", "r+"):
            #

        self.assertEqual()

    def test_batch(self):
        # Test the --batch flag
        # subprocess.Popen()
        pass 

    def test_config(self):

        # config = MpTcpAnalyzerConfig()
        cfg = MpTcpAnalyzerConfig("tests/test_config.ini")
        self.assertEqual(cfg["DEFAULT"]["tshark_binary"], "fake_tshark")

    @unittest.skip("Not sure pcap are valid yet")
    def test_mapping(self):
        # expects 2 datasets
        # load from csv
        ds1 = self.m.load_into_pandas("examples/node0.pcap")
        ds2 = self.m.load_into_pandas("examples/node1.pcap")
        ds1 = ds1[(ds1.mptcpstream == args.mptcp_client_id)]
                
        ds2 = ds2[ds2.mptcpstream == args.mptcp_server_id]
        # core.map_subflows_between_2_datasets ()

        self.m.do_plot("plot owd 0")

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

    def test_list_plots_misc(self):
#http://docs.openstack.org/developer/stevedore/managers.html#stevedore.extension.Extension
# plugin, obj
        self.m.plot_mgr.make_test_instance(
                [ Extension("misc", "mptcpanalyzer.plots.dsn:PerSubflowTimeVsX",
                    
# pkg_resources.
# entry_points.load
                    None
                    , 
                    mptcpanalyzer.plots.dsn.PerSubflowTimeVsX()
                    )]
                )
        plot_names = self.m._list_available_plots()
        self.assertIn("misc", plot_names)
        # self.assertIn("", plot_names)

    def test_list_plots_2(self):
        plot_names = self.m._list_available_plots()
        # self.assertIn("misc", plot_names)
        # self.assertIn("", plot_names)

    def test_generate_plots(self):
        self.m.do_load("examples/iperf-mptcp-0-0.pcap")
        # TODO precise file
        self.m.do_plot("plot dsn 0")
        self.m.do_plot("plot interarrival 0")

        # TODO 

    def test_generate_plot_ns3(self):

        self.m.do_plot("plot ns3 --meta examples/ cwnd 0")
    # def test_plot_dsn(self):
    #     self.m.do_plot("plot dsn 0")

