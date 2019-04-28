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
from mptcpanalyzer.debug import debug_dataframe
from mptcpanalyzer.data import classify_reinjections


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

        parser.description = inspect.cleandoc('''
            MPTCP goodput
        ''')

        parser.epilog = inspect.cleandoc('''
            > plot mptcp_gput examples/client_2_filtered.pcapng 0 examples/client_2_filtered.pcapng 0 --display
        ''')
        return parser


    def plot(self, pcap, pcapstream, fields, **kwargs):
        """

        """
        fig = plt.figure()
        axes = fig.gca()
        fields = ["tcpdest", "tcpstream", "mptcpdest"]
        df = pcap

        df.mptcp.fill_dest(pcapstream)
        # df = df[ df.mptcpstream == ]

        dfc = classify_reinjections(df)

        # then it's the same as for throughput
        dfc = dfc[ dfc.redundant == False ]


        for idx, subdf in df.groupby(_sender(fields), sort=False):

            print("t= %r" % (idx,))
            print("len= %r" % len(subdf))
            tcpdest, tcpstream, mptcpdest = idx

            # if protocol == tcpdest not in kwargs.destinations:
            #     log.debug("skipping TCP dest %s" % tcpdest)
            #     continue


            # if tcpdest
            # df = debug_convert(df)
            pplot = subdf.plot(
                # gca = get current axes (Axes), create one if necessary
                ax=axes,
                legend=True,
                # TODO should depend from
                x=_sender("abstime"),
                y="owd",
                label="Subflow %d towards tcp %s" % (tcpstream, tcpdest), # seems to be a bug
                # grid=True,
                # xticks=tcpstreams["reltime"],
                # rotation for ticks
                # rot=45,
                # lw=3
            )



