
from unittest import TestCase

import mptcpanalyzer as mp
from mptcpanalyzer.cli import MpTcpAnalyzer
from mptcpanalyzer.config import MpTcpAnalyzerConfig
from stevedore.extension import Extension



class PluginsTest(TestCase):

    def setUp(self):

        config = MpTcpAnalyzerConfig()

        self.m = MpTcpAnalyzer(config)

        plugins= [ 
            #name , entry point, plugin, obj
            Extension("hello", 'mptcpanalyzer.command_example:',
                None , mp.command_example.CommandExample() )
        ]
        mgr = self.m.cmd_mgr.make_test_instance(plugins)
        self.m.load_plugins(mgr)

    def test_hello(self):
        # should print the string attached
        self.m.do_hello("hello")
