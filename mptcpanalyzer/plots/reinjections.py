import mptcpanalyzer as mp
import mptcpanalyzer.plot as plot
import pandas as pd
import logging
import argparse
import inspect
import matplotlib.pyplot as plt
from typing import List, Any, Tuple, Dict, Callable, Set
from mptcpanalyzer import _receiver, _sender, PreprocessingActions
from mptcpanalyzer.parser import gen_bicap_parser, gen_pcap_parser, MpTcpAnalyzerParser
from mptcpanalyzer.data import classify_reinjections

# I want to plot a CDF of the reinjection delays

log = logging.getLogger(__name__)



# plot reinjections
# skip subflows should 
# PerSubflow
# TODO plot cdf
# classify_reinjections
# https://stackoverflow.com/questions/25577352/plotting-cdf-of-a-pandas-series-in-python
class PlotMpTcpReinjections(plot.Matplotlib):
    """
    Plot MPTCP level attributes
    This should be the most straightforward plot.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


    def default_parser(self, *args, **kwargs):

        parser = gen_bicap_parser("mptcp", True)
        res = super().default_parser(
            *args, parents=[parser],
            # direction=True,
            # skip_subflows=True,
            **kwargs
        )
        parser.description="Plot MPTCP subflow attributes over time"
        parser.epilog = inspect.cleandoc('''
            Example:
            > plot reinject examples/client_2_filtered.pcapng 0 examples/client_2_filtered.pcapng 0 --display


            > plot reinject examples/client_2_redundant.pcapng 1 examples/server_2_redundant.pcapng 1 --display
        ''')

        return res


    # TODO filter dest
    # https://stackoverflow.com/questions/25577352/plotting-cdf-of-a-pandas-series-in-python
    def plot(self, pcap, pcapstream, **kwargs):
        """
        getcallargs
        """
        df = pcap

        # Need to compute reinjections
        df.mptcp.fill_dest(pcapstream)
        df = classify_reinjections(df)

        fig = plt.figure()
        # tcpstreams = dat.groupby('tcpstream')

        # log.info("%d streams in the MPTCP flow" % len(tcpstreams))
        log.info("Plotting reinjections ")
        # log.info("len(df)= %d" % len(df))

        axes = fig.gca()

        fields = ["tcpstream", "mptcpdest"]

        fig.suptitle("Reinjections CDF " ,
            verticalalignment="top",
            # x=0.1, y=.95,
            )

        # il n'a pas encore eu les destinations !!
        print("DATASET HEAD")
        print(df.head())
        for idx, subdf in df.groupby(_sender(fields), sort=False):
            log.info("len(df)= %d" % len(df))

            # TODO check destination
            # TODO skip if no reinjection
            print("DATASET HEAD")
            print(df.head())

            # for idx, (streamid, ds) in enumerate(tcpstreams):
            # subdf[_sender("reinj_delta")].plot.line(
            #     x="abstime",
            #     ax=axes,
            #     # use_index=False,
            #     legend=False,
            #     grid=True,
            # )
            subdf[_sender("reinj_delta")].hist(cumulative=True, density=1, bins=100)

        axes.set_xlabel("Time (s)")
        axes.set_ylabel("Reinjection delay")

        handles, labels = axes.get_legend_handles_labels()

        # Generate "subflow X" labels
        # location: 3 => bottom left, 4 => bottom right
        axes.legend(
            handles,
            ["Subflow %d" % (x) for x, _ in enumerate(labels)],
            loc=4
        )
        return fig
