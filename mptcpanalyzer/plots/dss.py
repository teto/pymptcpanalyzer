#!/usr/bin/env python
# -*- coding: utf-8 -*-

import mptcpanalyzer.plot as plot
import panda as pd
import matplotlib.pyplot as plt
import os

class TimeVsDsn(plot.Plot):
    
    def __init__(self):
        # super(self, "dsn")
        pass

    # def plot(self, data, *args, **kwargs):
    def plot(self, data, args): # *args, **kwargs):
        print("data=", data) 
        print("args", args)
        # parser = plot.Plot.default_parser()
        # args = parser.parse_args(*args)
        dat = data[data.mptcpstream == args.mptcpstream]
        if not len(dat.index):
            print("no packet matching mptcp.stream %d" % args.mptcpstream)
            return
        
        # dssRawDSN could work as well
        # plot (subplots=True)
        fig = plt.figure()
        plt.title("hello world")
        # ax = tcpstreams[args.field].plot(ax=fig.gca())
        # want 
        # columns allows to choose the correct legend
        # df = self.data
        dat.set_index("reltime", inplace=True)
        tcpstreams = dat.groupby('tcpstream')
        # print(df)
        # TODO how to draw arrows with
        # ax.arrow(0, 0, 0.5, 0.5, head_width=0.05, head_length=0.1, fc='k', ec='k')
        field = "dss_dsn"
        # dss_length
        pplot = tcpstreams[field].plot(ax=fig.gca(),
            # x=tcpstreams["reltime"],
            # x="Relative time", # ne marche pas
            title="Data Sequence Numbers over subflows", 
            # use_index=False,
            # legend=True,
            lw=3
            )


        ax = fig.gca()
        # print(dir(pplot))
        # pplot.ax
        ax.set_xlabel("Relative time")
        # pplot.set_xlabel("Time")
        # ax.set_ylabel("DSN")
        # fig = ax.get_figure()
        # for axes in plot:
            # print("Axis ", axes)
            # fig = axes.get_figure()
            # fig.savefig("/home/teto/test.png")
        # fig = plot.get_figure()
        args.out = os.path.join(os.getcwd(), args.out)
        fig.savefig(args.out)
        return True

