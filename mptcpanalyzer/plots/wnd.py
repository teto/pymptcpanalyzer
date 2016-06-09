#!/usr/bin/env python
# -*- coding: utf-8 -*-
import mptcpanalyzer.plot as plot
import pandas as pd
import matplotlib.pyplot as plt
import os


class Rwnd(plot.Plot):

    def __init__(self):
        # super(self, "dsn")
        pass

    def plot(self, data, args):
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

        dat.set_index("reltime", inplace=True)
        dat["rwnd"].plot.line(
            title="Receive window", 
            # use_index=False,
            legend=True,
            # style="-o",
            grid=True,
            # xticks=tcpstreams["reltime"],
            # rotation for ticks
            # rot=45, 
            lw=1
        )
        args.out = os.path.join(os.getcwd(), args.out)
        print("Saving into %s" % (args.out))
        fig.savefig(args.out)
        return True
