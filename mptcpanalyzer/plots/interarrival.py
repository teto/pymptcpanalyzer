#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import mptcpanalyzer.plot as plot
# import mptcpanalyzer as mp
# from mptcpanalyzer.connection import MpTcpConnection
import pandas as pd
import logging
import argparse
import matplotlib.pyplot as plt
import collections

log = logging.getLogger(__name__)


class CrossSubflowInterArrival(plot.Matplotlib):
    """
    Compute arrival of new *attribute*
    """

    def default_parser(self):
        parser = super().default_parser()
        # parser.add_argument("--x-subflows", action="store_true", dest="crosssubflows",
                # help="Consider only cross-subflow arrivals")
        parser.add_argument("sender_ips", nargs="+",
                help="list sender ips here to filter the dataset")
        return parser

    def plot(self, main, args, **kwargs):
        """
        goal is here to generate a new Dataframe that lists only switchings between
        subflows for DSN arrival
        """
        # print("data=", data)
        print("args", args)
        data = main.data
        dat = self.filter_ds(data, mptcpstream=args.mptcpstream, srcip=args.sender_ips)

        tcpstreamcol = dat.columns.get_loc("tcpstream")

        # TODO try replacing with dat.empty
        if not len(dat.index):
            print("no packet matching query %s" % query)
            return

        print("toto len=", len(dat))
        df = pd.DataFrame([], columns=['from', 'to', 'delta'])
        # as we just ran a query, we need to reindex it to have contiguous indexes
        dat.reset_index(drop=True, inplace=True)
        print(dat.index[1:])
        for i in dat.index[1:]:
            pass
            if dat.iloc[i-1, tcpstreamcol] != dat.iloc[i, tcpstreamcol]:
                # print("index i:", dat.iloc[i])
                # TODO check if buggy , idx vs row ?
                row = {
                    'from': dat.iloc[i-1, tcpstreamcol],
                    'to':   dat.iloc[i, tcpstreamcol],
                     'delta': dat.loc[i,"reltime"] - dat.loc[i-1,"reltime"]
                     }

                # print("append row " , row)
                df = df.append(row, ignore_index=True)

        print( "head", df.head() )

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
    TODO rename into interDSN ?
    In case traffic is biderctional we must filter on one direction only
    TODO this is wrong
    """
    available = [
            "dsn",
            "dack"
            ]

    def __init__(self, *args, **kwargs):
        inputs = [
        ]
        super().__init__(*args, **kwargs)

    def default_parser(self):
        parser = super().default_parser()
        # parser.add_argument("--x-subflows", action="store_true", dest="crosssubflows", help="Consider only cross-subflow arrivals")
        parser.add_argument("attribute", choices=self.available, help="interarrival between which numbers")
        parser.add_argument("sender_ips", nargs="+",
                help="list sender ips here to filter the dataset")
        return parser

    def plot(self, main, args, **kwargs):
        data = main.data
        dat = self.filter_ds(data, mptcpstream=args.mptcpstream, ipsrc=args.sender_ips)

        # filter to only account for one direction (departure or arrival)
        # TODO try replacing with dat.empty
        if not len(dat.index):
            print("no packet matching query ")
            return

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

