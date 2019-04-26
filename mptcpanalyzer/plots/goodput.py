# -*- coding: utf-8 -*-
import mptcpanalyzer as mp
from mptcpanalyzer import _receiver, _sender, PreprocessingActions
import mptcpanalyzer.plot as plot
import mptcpanalyzer.data as woo
from mptcpanalyzer.connection import MpTcpConnection, TcpConnection
import pandas as pd
import logging
import matplotlib.pyplot as plt
import matplotlib as mpl
import os
import inspect
import collections
from mptcpanalyzer.cache import CacheId
from mptcpanalyzer.parser import gen_bicap_parser, gen_pcap_parser, MpTcpAnalyzerParser
from cmd2 import argparse_completer
from typing import Iterable, List #, Any, Tuple, Dict, Callable
from itertools import cycle
from mptcpanalyzer.pdutils import debug_dataframe


log = logging.getLogger(__name__)



class MptcpGoodput(plot.Matplotlib):
    """

    Classify reinjections and ditch packets which are useless, otherwise, do the same as
    as throughput
    """
    def default_parser(self, *args, **kwargs):

        parser = MpTcpAnalyzerParser(
            description=inspect.cleandoc("""
                Plot goodput (discard reinjections etc) of subflows and of the aggregated
            """)
        )


        expected_pcaps = {
            "pcap": PreprocessingActions.MergeMpTcp | PreprocessingActions.FilterDestination,
        }

        temp = gen_pcap_parser(input_pcaps=expected_pcaps, parents=[super().default_parser()])
        subparser = subparsers.add_parser(protocol, parents=[temp, ],
                add_help=False)

        parser.description = inspect.cleandoc('''
            Helps plotting One Way Delays between tcp connections
        ''')

        parser.epilog = inspect.cleandoc('''
            Example for TCP:
            > plot owd tcp examples/client_2_filtered.pcapng 0 examples/server_2_filtered.pcapng 0 --display

            And for MPTCP:
            > plot owd mptcp examples/client_2_filtered.pcapng 0 examples/client_2_filtered.pcapng 0 --display
        ''')
        return parser


