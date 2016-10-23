#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import mptcpanalyzer.plot as plot
# import mptcpanalyzer as mp
# from mptcpanalyzer.connection import MpTcpConnection
import pandas as pd
import logging
import argparse
import matplotlib.pyplot as plt
from mptcpanalyzer import fields_v2
# import inspect

log = logging.getLogger(__name__)


class PerSubflowTimeVsAttribute(plot.Matplotlib):
    """
    Plot one or several mptcp attributes (dsn, dss, etc...) on a same plot.
    This should be the most straightforward plot.

    """
    mptcp_attributes = dict((x.name, x.label) for x in fields_v2() if x.label)

    def __init__(self, *args, **kwargs):
        pcaps = {"pcap": plot.PreprocessingActions.PreloadAndFilter}
        super().__init__(preload_pcaps=pcaps, *args, **kwargs)


    def default_parser(self, *args, **kwargs):

        parent = argparse.ArgumentParser(
            description="Helps plotting Data sequence numbers"
        )
        # parent.add_argument("pcap", action="store", help="Input pcap")
        parser = super().default_parser(*args, parent_parsers=[parent], 

                mptcpstream=True,
                direction=True, skip_subflows=True, **kwargs)
        parser.add_argument('field', choices=self.mptcp_attributes.keys(),
                help="Choose an mptcp attribute to plot")
        return parser


    def plot(self, dat, mptcpstream, field=None, **kwargs):
        """
        getcallargs
        """

        # inspect.getfullargspec(fileinput.input))
        # dataframes = [ plotter.preprocess(df, **dargs) for df in dataframes ]
        # dat = rawdf

        fig = plt.figure()
        tcpstreams = dat.groupby('tcpstream')

        print("%d streams in the MPTCP flow" % len(tcpstreams))
        print("Plotting field %s" % field)

        # gca = get current axes (Axes), create one if necessary
        axes = fig.gca()

        for idx, (streamid, ds) in enumerate(tcpstreams):
            ds[field].plot.line(
                ax=axes,
                # use_index=False,
                legend=False,
                grid=True,
            )

        axes.set_xlabel("Time (s)")
        axes.set_ylabel(self.mptcp_attributes[field])

        handles, labels = axes.get_legend_handles_labels()

        # Generate "subflow X" labels
        # location: 3 => bottom left, 4 => bottom right
        axes.legend(handles, [ "%s for Subflow %d" % (field, x) for x, _ in enumerate(labels) ], loc=4)

        return fig


