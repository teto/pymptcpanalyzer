#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import mptcpanalyzer.plot as plot
import mptcpanalyzer as mp
from mptcpanalyzer.connection import MpTcpConnection
import pandas as pd
import logging
import matplotlib.pyplot as plt
import os
from mptcpanalyzer import fields_v2

log = logging.getLogger(__name__)

class DssLengthHistogram(plot.Matplotlib):
    """
    Plots histogram

    .. warning:: WIP
    """

    def __init__(self):
        super().__init__(title="DSS Length")

    def plot(self, df, mptcpstream, **kwargs):
        # data = main.data
        # dat = data[data.mptcpstream == args.mptcpstream]
        # if not len(dat.index):
        #     print("no packet matching mptcp.stream %d" % args.mptcpstream)
        #     return

        fig = plt.figure()
        axes = fig.gca()
        df.set_index("reltime", inplace=True)
        # tcpstreams = dat.groupby('tcpstream')
        field = "dss_length"
        pplot = df[field].plot.hist(
            ax=axes,
            legend=True,
            grid=True,
        )
        return fig


class DSSOverTime(plot.Matplotlib):
    """
    WIP
    Draw small arrows with dsn as origin, and a *dss_length* length etc...
    Also allow to optionally display dataack

    As the generated plot can end up being quite rich, it is a good idea to specify 
    a |matplotlibrc| with high dimensions and high dpi.

    Todo:
        Adds
    """

    def __init__(self):
        super().__init__(self, "dsn", False)

    def default_parser(self, *args, **kwargs):
        parser = super().default_parser(*args, mptcpstream=True, 
                direction=True, **kwargs)
        parser.add_argument('--dack', action="store_true", default=False,
                help="Adds data acks to the graph")
        return parser

    def plot(self, rawdf, destination, dack=False, **args):
        """
        Might be 
        """
        # dat = data[data.mptcpstream == args.mptcpstream]
        # if not len(dat.index):
        #     ("no packet matching mptcp.stream %d" % args.mptcpstream)
        #     return
        df_forward = self.preprocess(rawdf, **args)
        print("**args=%s" % (args))
        # if args.destination == Destination:
        # args.update(destination="toto")
        print(args)
        df_backward = self.preprocess(rawdf, **args, destination=mp.reverse_destination(destination))
        # if dack:
        #     df_backward = self.preprocess(rawdf, **args, direction=Directinalon.)

        dat = df_forward[df_forward.dss_dsn >= 0]
        
        # tout ceux ou c pas nan
        # df_backward = df_backward[df_forward.dack >=0]

        # best might be this
        # http://matplotlib.org/api/pyplot_api.html#matplotlib.pyplot.quiver
        # plt.quiver( dat.reltime, dat.dss_dsn, [0]* len(dat.dss_dsn) ,  dat.dss_length, scale_units="xy", scale=1, angles="xy",)
        fig = plt.figure()
        axes = fig.gca()
        dat.set_index("reltime", inplace=True)

        # quiver(X, Y, U, V, **kw)

        # TODO groupby subflows so that we can have different colors
        print( dat.head())
        # plt.quiver(
        #         dat.reltime, # X
        #         dat.dsn, # Y
        #         [0]* len(dat.dss_dsn) ,
        #        dat.dss_length,
        #        scale_units="xy", scale=3, angles="xy",
        # )
        # dss_dsn
        dat["dss_dsn"].plot.line(ax=axes)

        def show_dss(idx, row,):
            """
            dss_dsn
            """
            # print(row["dss_dsn"])
            # x , y, dx, dy, **kwarg
# row["dss_dsn"]
            # axes.arrow(row["reltime"], 0 , 0, row["dss_length"], head_width=0.05, head_length=0.1, fc='k', ec='k')
            axes.arrow(idx, int(row["dss_dsn"]) , 0, row["dss_length"]*100,
                    head_width=0.05, head_length=0.1, fc='k', ec='k')
    # for row in DataFrame.itertuples(index=True):
    # for i in range(0, len(df)):
    # print df.iloc[i]['c1'], df.iloc[i]['c2']
        # df.apply(show_dss)

        # TODO pass as argument or upscale the figure dimension
        downsampling = 100
            

        axes.set_ylabel("Data Sequence Number (DSN)")
        axes.set_xlabel("Relative time (s)")

        # does not preserve dtypes !
        # http://pandas.pydata.org/pandas-docs/stable/generated/pandas.DataFrame.iterrows.html
        i = 0
        print(dat[ ["ipdst", "ipsrc"] ].tail(2))
        # df_by_streams = dat.groupby('tcpstream')
        # df_by_streams
        for tcpstream, df in dat.groupby('tcpstream'):
            for index, row in dat.iterrows():
                # print("%r" % row)
                # print("%r" % row["dss_dsn"])
                i += 1
                if not i % downsampling:
                    show_dss(index, row)
        return fig


