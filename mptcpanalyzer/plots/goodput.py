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
from typing import Iterable, List  # Any, Tuple, Dict, Callable
from itertools import cycle
from mptcpanalyzer.debug import debug_dataframe
from mptcpanalyzer.data import classify_reinjections
from mptcpanalyzer.plots.throughput import compute_throughput, tput_parser, plot_tput
from functools import partial

log = logging.getLogger(__name__)


class MptcpGoodput(plot.Matplotlib):
    """
    Classify reinjections and ditch packets which are useless, otherwise, do the same as
    as throughput
    """

    def __init__(self, *args, **kwargs):
        super().__init__(
            *args,
            title="MPTCP goodput",
            x_label="Time (s)",
            y_label="Goodput (bytes/s)",
            **kwargs
        )

    def default_parser(self, *args, **kwargs):

        parser = MpTcpAnalyzerParser(
            description=inspect.cleandoc("""
                Plot goodput (discard reinjections etc) of subflows and of the aggregated
            """)
        )

        expected_pcaps = {
            "pcap": PreprocessingActions.MergeMpTcp | PreprocessingActions.FilterDestination,
        }

        temp = gen_pcap_parser(
            input_pcaps=expected_pcaps, parents=[super().default_parser()]
        )

        parser.description = inspect.cleandoc('''
            MPTCP goodput
        ''')

        parser.epilog = inspect.cleandoc('''
            > plot mptcp_gput examples/client_2_filtered.pcapng 1 examples/server_2_filtered.pcapng 1 --display
        ''')

        temp = tput_parser(temp)
        return temp


    def plot(self, pcap, pcapstream, window, **kwargs):
        """
        Should be very similar to the thoughput one, except with

        """
        fig = plt.figure()
        axes = fig.gca()
        fields = ["tcpdest", "tcpstream", "mptcpdest"]

        # TODO this should be configured in the parser
        # destinations = kwargs.get("destinations", list(mp.ConnectionRoles))
        destinations = kwargs.get("pcap_destinations")
        skipped = kwargs.get("skipped_subflows", [])
        df = pcap

        # df Classified
        df_classified = classify_reinjections(df)

        # then it's the same as for throughput
        log.debug("Dropping redundant packets")
        df_useful = df_classified[df_classified.redundant == False]
        df_useful = df_useful.copy()
        df_useful.dropna(axis="index", subset=[_sender("abstime")], inplace=True,)
        # print("after dropna")
        # print(df_useful)

        pd_abstime = pd.to_datetime(df_useful[_sender("abstime")], unit="s", errors="raise")
        # print("DEBUG ATTEMPT")
        # print(pd_abstime)

        df_useful.set_index(pd_abstime, inplace=True)
        df_useful.sort_index(inplace=True)

        suffix = " towards MPTCP {mptcpdest}"

        label_fmt = "Subflow {tcpstream}" + label_suffix
        if len(destinations) == 1:
            # TODO as we look at acks, it should be swapped !
            self.title = self.title + suffix
        else:
            # label_suffix = suffix
            label_fmt = label_fmt + " towards MPTCP {mptcpdest}"


        for idx, subdf in df_useful.groupby(_sender(fields), as_index=False, sort=False):

            # print("len= %r" % len(subdf))
            tcpdest, tcpstream, mptcpdest = idx
            print("tcpdest= %r, tcpstream %r mptcpdest %r" % (tcpdest, tcpstream, mptcpdest))

            if mptcpdest not in destinations:
                log.debug("skipping MPTCP dest %s" % tcpdest)
                continue

            if tcpstream in skipped:
                log.debug("skipping subflow %d" % tcpstream)
                continue

            # log.debug("plotting MPTCP dest %s" % tcpdest)
            # if len(destinations) >= 2:
            #     label_fmt = label_fmt + suffix

            plot_tput(
                fig,
                # subdf["dack"],
                subdf["tcplen"],
                subdf.index,  # no need
                window,
                label=label_fmt.format(tcpstream=tcpstream,
                    mptcpdest=mp.ConnectionRoles(mptcpdest).to_string()),
            )

        # then plots MPTCP level throughput
        ##################################################
        for mptcpdest, subdf in df_useful.groupby("mptcpdest"):
            # tcpdest, tcpstream, mptcpdest = idx
            if mptcpdest not in destinations:
                log.debug("Ignoring destination %s", mptcpdest)
                continue

            log.debug("Plotting mptcp destination %s", mptcpdest)

            # add id
            label_fmt = "MPTCP stream" + label_suffix
            plot_tput(
                fig,
                subdf["tcplen"],
                subdf["abstime"],
                window,
                label=label_fmt.format(tcpstream=tcpstream, mptcpdest=mp.ConnectionRoles(mptcpdest).to_string()),
            )

        print("dest: " % destinations)

        return fig
