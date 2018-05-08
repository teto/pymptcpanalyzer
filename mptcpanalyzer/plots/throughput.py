#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import mptcpanalyzer.plot as plot
import pandas as pd
import argparse
import matplotlib.pyplot as plt
from mptcpanalyzer.statistics import mptcp_compute_throughput
import collections
from typing import List


class SubflowThroughput(plot.Matplotlib):
    """
    Plot subflow throughput
    Mptcp throughput equals the sum of subflow contributions
    """

    def __init__(self, *args, **kwargs):
        pcaps = [("pcap", plot.PreprocessingActions.Preload | plot.PreprocessingActions.FilterMpTcpStream), ]
        super().__init__(
            *args,
            input_pcaps=pcaps,
            **kwargs
        )

    def default_parser(self, *args, **kwargs):

        parent = argparse.ArgumentParser(
            description="Helps plotting Data sequence numbers"
        )
        # parent.add_argument("pcap", action="store", help="Input pcap")
        parser = super().default_parser(
            *args, parent_parsers=[parent],
            mptcpstream=True,
            direction=True,
            skip_subflows=True,
            **kwargs)
        # parser.add_argument('field', choices=self.mptcp_attributes.keys(),
            # help="Choose an mptcp attribute to plot")
        return parser

    def plot(self, dat, mptcpstream, destination, **kwargs):
        """
        getcallargs
        """

        fig = plt.figure()
        success, ret = mptcp_compute_throughput(dat, mptcpstream, destination)
        if success is not True:
            print("Failure: %s", ret)
            return

        data = map(lambda x: x['bytes'], ret['subflow_stats'])
        s = pd.DataFrame(data=pd.Series(data))
        print (s)

        # gca = get current axes (Axes), create one if necessary
        axes = fig.gca()
        s.T.plot.bar(stacked=True, by=None, ax=axes);
        # pd.Series
        # .hist(
        # for idx, (streamid, ds) in enumerate(tcpstreams):
        #     ds[field].plot.line(
        #         ax=axes,
        #         # use_index=False,
        #         legend=False,
        #         grid=True,
        #     )

        axes.set_xlabel("Time (s)")
        axes.set_ylabel("contribution")

        # handles, labels = axes.get_legend_handles_labels()

        # # Generate "subflow X" labels
        # # location: 3 => bottom left, 4 => bottom right
        # axes.legend(
        #     handles,
        #     ["%s for Subflow %d" % (field, x) for x, _ in enumerate(labels)],
        #     loc=4
        # )

        return fig
