#!/usr/bin/env python
# -*- coding: utf-8 -*-

import mptcpanalyzer.plot as plot
import pandas as pd
import matplotlib.pyplot as plt
import os

class DssSizeHistogram(plot.Plot):

    # def plot(self, data, *args, **kwargs):
    def plot(self, data, args): # *args, **kwargs):
        # print("data=", data) 
        print("args", args)
        
        dat = data[data.mptcpstream == args.mptcpstream]
        if not len(dat.index):
            print("no packet matching mptcp.stream %d" % args.mptcpstream)
            return

        ax = dat.latency.plot.hist(
            legend=False,
            grid=True,
            bins=10,
        )   
        ax.set_xlabel("")
        ax.set_ylabel("Latency")
        fig = ax.get_figure()

        args.out = os.path.join(os.getcwd(), args.out)
        print("Saving into %s" % (args.out))
        fig.savefig(args.out)
        return True
