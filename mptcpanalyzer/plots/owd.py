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

# global log and specific log
log = logging.getLogger(__name__)


TCP_DEBUG_FIELDS = ['hash', 'ipsrc', 'ipdst', 'tcpstream', 'packetid', "reltime", "abstime", "tcpdest", "mptcpdest"]


class TcpOneWayDelay(plot.Matplotlib):
    """
    The purpose of this plot is to display the "one-way delay" (OWD) (also called
    one-way latency (OWL)) between the client
    and the server.
    To do this, you need to capture a communication at both ends, client and server.

    Wireshark assigns an id (mptcp.stream) to each mptcp communications, ideally this plugin
could try to match both ids but for now you need

    .. note:: both hosts should have their clock synchronized. If this can be hard
    with real hosts, perfect synchronization is available in network simulators
    such as ns3.


    This format allows

    .. _owd-cache-format:
        It creates an intermediate cache file of the form
        host1pktId, host2pktId, score, owd, ipsrc_h1, ipsrc_h2, etc...


    .. warning:: This plugin is experimental.
    """

    def __init__(self, *args, **kwargs):

        super().__init__(
            *args,
            # input_pcaps=expected_pcaps,
            **kwargs
        )

        self.tshark_config.filter = "tcp";
        # print("owd tcp", self.tshark_config.fields)
        # TODO a purer version would be best


    # TODO simplify
    def default_parser(self, *args, **kwargs):
        parser = MpTcpAnalyzerParser(
            description=inspect.cleandoc("""
                Plot One Way Delays"
            """)
        )

        subparsers = parser.add_subparsers(dest="protocol",
            title="Subparsers", help='sub-command help',)
        subparsers.required = True  # type: ignore

        orig_actions = {
            "tcp": PreprocessingActions.MergeTcp | PreprocessingActions.FilterDestination,
            "mptcp": PreprocessingActions.MergeMpTcp | PreprocessingActions.FilterDestination,
        }

        for protocol, actions in orig_actions.items():

            expected_pcaps = {
                "pcap": actions
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

        # here we recompute the OWDs

    def plot(self, pcap, protocol, **kwargs):
        """
        Ideally it should be mapped automatically
        For now plots only one direction but there could be a wrapper to plot forward owd, then backward OWDs
        Disclaimer: Keep in mind this assumes a perfect synchronization between nodes, i.e.,
        it relies on the pcap absolute time field.
        While this is true in discrete time simulators such as ns3

        """
        fig = plt.figure()
        axes = fig.gca()
        res = pcap
        res[_sender("abstime")] = pd.to_datetime(res[_sender("abstime")], unit="s")


        # TODO here we should rewrite
        debug_fields = _sender(TCP_DEBUG_FIELDS) + _receiver(TCP_DEBUG_FIELDS) + [ "owd" ]

        # print("columns", pcap)
        debug_dataframe(res, "owd dataframe")
        print(res.loc[res.merge_status == "both", debug_fields ])

        df = res

        print("STARTING LOOP")
        print("DESTINATION=%r" % kwargs.get("pcapdestinations", []))
        # df= df[df.owd > 0.010]

        fields = ["tcpdest", "tcpstream", ]
        # if True:
        if protocol == "mptcp":
            self.plot_mptcp(df, fig, fields, **kwargs )
        else:
            self.plot_tcp(df, fig, fields, **kwargs )


        # TODO add units
        axes.set_xlabel("Time (s)")
        axes.set_ylabel("One Way Delay (s)")

        self.title = "One Way Delays for {} streams {} <-> {} {dest}".format(
            protocol,
            kwargs.get("pcap1stream"),
            kwargs.get("pcap2stream"),
            dest= ""
        )

        return fig


    def plot_tcp(self, df, fig, fields, **kwargs):
        axes = fig.gca()
        # fields = ["tcpdest", "tcpstream"]

        # ConnctionRole doesn't support <
        for idx, subdf in df.groupby(_sender(fields), sort=False):

            # print("t= %r" % (idx,))
            print("len= %r" % len(subdf))
            tcpdest, tcpstream = idx

            # print("tcpdest= %r" % tcpdest)
            # print("=== less than 0\n", subdf[subdf.owd < 0.050])
            # print("=== less than 0\n", subdf.tail())

            # if tcpdest
            # df = debug_convert(df)
            debug_dataframe(subdf, "subdf stream %d destination %r" % (tcpstream, tcpdest))
            pplot = subdf.plot.line(
                # gca = get current axes (Axes), create one if necessary
                ax=axes,
                legend=True,
                # TODO should depend from
                x=_sender("abstime"),
                y="owd",
                label="Stream %d towards %s" % (tcpstream, tcpdest), # seems to be a bug
                # grid=True,
                # xticks=tcpstreams["reltime"],
                # rotation for ticks
                # rot=45,
                # lw=3
            )

    def plot_mptcp(self, df, fig, fields, **kwargs):
        axes = fig.gca()
        fields = ["tcpdest", "tcpstream", "mptcpdest"]

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


