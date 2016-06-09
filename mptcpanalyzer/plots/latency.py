#!/usr/bin/env python
# -*- coding: utf-8 -*-

import mptcpanalyzer.plot as plot
import pandas as pd
import matplotlib.pyplot as plt
import os


class SmoothedRtt(plot.Plot):
    # TODO provide several versions; one with histograms for instance
    """
    Excerpt from :
    http://sgros.blogspot.fr/2012/02/calculating-tcp-rto.html
    In order to achieve that, two new variables are introduced, smoothed RTT, or short SRTT, and RTT variance, or RTTVAR. Those two variables are updated, whenever we have a new RTT measurement, like this (taken from the RFC6298):

        RTTVAR <- (1 - beta) * RTTVAR + beta * |SRTT - R'|
        SRTT <- (1 - alpha) * SRTT + alpha * R'

    alpha and beta are parameters that determine how fast we forget the past. 
    If this parameter is too small new measurements will have little influence on our 
    current understanding of expected RTT and we will slowly react to changes. 
    If, on the other hand, alpha approaches 1 then the past will not influence our current 
    estimation of RTT and it might happen that a single RTT was huge for whatever reason 
    and that suddenly we have wrong estimation. Not only that, but we could have erratic behavior of SRTT.
     So, alpha and beta parameters have to be carefully selected. 
    The values recommended by RFC are alpha=1/8 and beta=1/4.
    """
    alpha = 1 / 8
    beta = 1 / 4

    def __init__(self):
        # super(self, "dsn")
        pass

    # def _generate_plot(self, data, *args, **kwargs):
    def _generate_plot(self, data, args):
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
        # plt.title("hello world")
        # ax = tcpstreams[args.field].plot(ax=fig.gca())
        # want 
        # columns allows to choose the correct legend
        # df = self.data
        dat.set_index("reltime", inplace=True)
        tcpstreams = dat.groupby('tcpstream')
        # print(df)
        field = "dsn"
        pplot = tcpstreams[field].plot.line(
            # gca = get current axis
            ax=fig.gca(),
            # x=tcpstreams["reltime"],
            # x="Relative time", # ne marche pas
            title="Data Sequence Numbers over subflows", 
            # use_index=False,
            legend=True,
            # style="-o",
            grid=True,
            # xticks=tcpstreams["reltime"],
            # rotation for ticks
            # rot=45, 
            # lw=3
        )   
        # patches1, labels1 = ax1.get_legend_handles_labels()
        # ax.legend()
        # print(dir(pplot))
        # ax = pplot.axes[0].get_figure()
        ax = fig.gca()
        # print(dir(pplot))
        # pplot.ax
        # fig.set_xlabel("Relative time")
        # pplot.set_xlabel("Time")
        # ax.set_ylabel("DSN")
        # fig = ax.get_figure()
        # for axes in plot:
        # print("Axis ", axes)
        # fig = axes.get_figure()
        # fig.savefig("/home/teto/test.png")
        # fig = plot.get_figure()
        args.out = os.path.join(os.getcwd(), args.out)
        print("Saving into %s" % (args.out))
        fig.savefig(args.out)
        return True


# TODO provide several versions; one with histograms for instance
class DsnVsLatency(plot.Matplotlib):

    def __init__(self):
        # super(self, "dsn")
        pass

    # def _generate_plot(self, data, *args, **kwargs):
    def _generate_plot(self, main, args): # *args, **kwargs):
        data = main.data
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
        # plt.title("hello world")
        # ax = tcpstreams[args.field].plot(ax=fig.gca())
        # want 
        # columns allows to choose the correct legend
        # df = self.data
        dat.set_index("reltime", inplace=True)
        tcpstreams = dat.groupby('tcpstream')
        # print(df)
        field = "dsn"
        pplot = tcpstreams[field].plot.line(
            # gca = get current axis
            ax=fig.gca(),
            # x=tcpstreams["reltime"],
            # x="Relative time", # ne marche pas
            title="Data Sequence Numbers over subflows", 
            # use_index=False,
            legend=True,
            # style="-o",
            grid=True,
            # xticks=tcpstreams["reltime"],
            # rotation for ticks
            # rot=45, 
            # lw=3
        )   
        # patches1, labels1 = ax1.get_legend_handles_labels()
        # ax.legend()
        # print(dir(pplot))
        # ax = pplot.axes[0].get_figure()
        ax = fig.gca()
        # print(dir(pplot))
        # pplot.ax
        # fig.set_xlabel("Relative time")
        # pplot.set_xlabel("Time")
        # ax.set_ylabel("DSN")
        # fig = ax.get_figure()
        # for axes in plot:
        # print("Axis ", axes)
        # fig = axes.get_figure()
        # fig.savefig("/home/teto/test.png")
        # fig = plot.get_figure()
        args.out = os.path.join(os.getcwd(), args.out)
        print("Saving into %s" % (args.out))
        fig.savefig(args.out)
        return True


# TODO provide several versions; one with histograms for instance
class LatencyHistogram(plot.Matplotlib):

    def __init__(self):
        # super(self, "dsn")
        pass

    # def _generate_plot(self, data, *args, **kwargs):
    def _generate_plot(self, main, args):

        data = main.data
        dat = data[data.mptcpstream == args.mptcpstream]
        if not len(dat.index):
            print("no packet matching mptcp.stream %d" % args.mptcpstream)
            return

        ax = dat.latency.plot.hist(
            legend=False,
            grid=True,
            bins=10,
        )   
        ax.set_xlabel("Relative time")
        ax.set_ylabel("Latency")
        fig = ax.get_figure()
        return fig
