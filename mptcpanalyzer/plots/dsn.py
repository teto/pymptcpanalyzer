#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import mptcpanalyzer.plot as plot
# import mptcpanalyzer as mp
# from mptcpanalyzer.connection import MpTcpConnection
import pandas as pd
import logging
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
        super().__init__(preprocess_dataframes=True, *args, **kwargs)


    def default_parser(self, *args, **kwargs):

        parser = super().default_parser(*args, mptcpstream=True, direction=True,
                filter_subflows=True, **kwargs)
        parser.add_argument('field', choices=self.mptcp_attributes.keys(),
                help="Choose an mptcp attribute to plot")
        return parser


    def plot(self, dat,  mptcpstream, field=None, **kwargs):
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


class CrossSubflowInterArrival(plot.Matplotlib):
    """
    Compute arrival between updates of a *value* only when this
    update arrived from another subflow.

    .. warning: WIP
    """
    def default_parser(self, *args, **kwargs):
        parser = super().default_parser(*args, mptcpstream=True, direction=True, **kwargs)
        return parser

    def plot(self, rawdf, *args, **kwargs):
        """
        goal is here to generate a new Dataframe that lists only switchings between
        subflows for DSN arrival
        """

        # inspect.getfullargspec(fileinput.input))
        # dataframes = [ plotter.preprocess(df, **dargs) for df in dataframes ]
        tcpstreamcol = rawdf.columns.get_loc("tcpstream")

        # TODO try replacing with dat.empty
        if not len(rawdf.index):
            print("no packet matching query %s" % query)
            return

        df = pd.DataFrame([], columns=['from', 'to', 'delta'])
        # as we just ran a query, we need to reindex it to have contiguous indexes
        dat.reset_index(drop=True, inplace=True)
        print(dat.index[1:])
        for i in dat.index[1:]:
            pass
            if dat.iloc[i-1, tcpstreamcol] != dat.iloc[i, tcpstreamcol]:
                # print("index i:", dat.iloc[i])
                row = {
                    'from': dat.iloc[i-1, tcpstreamcol],
                    'to':   dat.iloc[i, tcpstreamcol],
                     'delta': dat.loc[i,"reltime"] - dat.loc[i-1,"reltime"]
                }

                # print("append row " , row)
                df = df.append(row, ignore_index=True)


    	# todrop.append(i-1)
        # if args.crosssubflows:
        # else:
        #     # compute delay between sending of
        #     # rename into "delays"
        #     dat["interdeparture"] = dat["reltime"] - dat["reltime"].shift()
        #     # need to compute interdeparture times
        ax = df.delta.plot.hist(
            legend=False,
            grid=True,
            bins=10,
        )

        ax.set_ylabel("Proportion")
        ax.set_xlabel("Inter DSN departure time")
        fig = ax.get_figure()

        return fig


class InterArrivalTimes(plot.Matplotlib):
    """
    Generate

    .. see: CrossSubflowInterArrival


    .. warning:: WIP
    """

    available = [
        "dsn",
        "dack"
    ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def default_parser(self, *args, **kwargs):
        parser = super().default_parser(*args, direction=True, **kwargs)
        # parser.add_argument("--x-subflows", action="store_true", dest="crosssubflows", help="Consider only cross-subflow arrivals")
        parser.add_argument("attribute", choices=self.available,
            help="interarrival between which numbers"
        )
        return parser

    def plot(self, dat, mptcpstream, *args, **kwargs):

        # inplace=True generates warning
        dat = dat.sort_values("dsn", ascending=True, )

        # compute delay between sending of
        # rename into "delays"
        dat["interdeparture"] = dat["reltime"] - dat["reltime"].shift()
        # need to compute interdeparture times
        ax = dat.interdeparture.plot.hist(
            legend=False,
            grid=True,
            bins=10,
        )

        ax.set_ylabel("Proportion")
        ax.set_xlabel("Inter DSN departure time")
        fig = ax.get_figure()

        return fig



