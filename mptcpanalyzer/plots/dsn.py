#!/usr/bin/env python
# -*- coding: utf-8 -*-

import mptcpanalyzer.plot as plot
import pandas as pd
import logging
import matplotlib.pyplot as plt
import os

log = logging.getLogger("mptcpanalyzer")

class AckInterArrivalTimes(plot.Plot):

    """
    TODO rename into interDSN ?
    In case traffic is biderctional we must filter on one direction only
    """

    def _generate_plot(self, data, args):
        # print("data=", data) 
        print("args", args)
        # parser = plot.Plot.default_parser()
        # args = parser.parse_args(*args)
        dat = data[data.mptcpstream == args.mptcpstream]
        # TODO try replacing with dat.empty
        if not len(dat.index):
            print("no packet matching mptcp.stream %d" % args.mptcpstream)
            return

        # TODO mptcp ack
        dat.sort_values("dack", ascending=True, inplace=True)
        
        # compute delay between sending of 
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

        args.out = os.path.join(os.getcwd(), args.out)
        print("Saving into %s" % (args.out))
        fig.savefig(args.out)
        return True



class CrossSubflowInterArrival(plot.Matplotlib):

    def default_parser(self):
        parser = super().default_parser()
        # parser.add_argument("--x-subflows", action="store_true", dest="crosssubflows", 
                # help="Consider only cross-subflow arrivals")
        parser.add_argument("sender_ips", nargs="+", 
                help="list sender ips here to filter the dataset")
        return parser

    def _generate_plot(self, data, args, **kwargs):
        """
        goal is here to generate a new Dataframe that lists only switchings between 
        subflows for DSN arrival
        """
        # print("data=", data) 
        print("args", args)
        # parser = plot.Plot.default_parser()
        # args = parser.parse_args(*args)

        query = " mptcpstream == %d and (" % args.mptcpstream
        # filter to only account for one direction (departure or arrival)
        # for ip in args.sender_ips:
        #     query += % ip
       # " or ".join( ipsrc == '{}' " 
        query_ipdst = map( lambda x: "ipdst == '%s'" % x, args.sender_ips)
        query += ' or '.join(query_ipdst)
        query += ")"

        # dat = data[data.mptcpstream == args.mptcpstream]
        log.debug("Running query %s" % query)
        dat = data.query(query)

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

        args.out = os.path.join(os.getcwd(), args.out)
        print("Saving into %s" % (args.out))
        fig.savefig(args.out)
        return True


class DsnInterArrivalTimes(plot.Matplotlib):
    """
    TODO rename into interDSN ?
    In case traffic is biderctional we must filter on one direction only
    """

    def default_parser(self):
        parser = super().default_parser()
        parser.add_argument("--x-subflows", action="store_true", dest="crosssubflows", 
                help="Consider only cross-subflow arrivals")
        parser.add_argument("sender_ips", nargs="+", 
                help="list sender ips here to filter the dataset")
        return parser

    def _generate_plot(self, data, args, **kwargs):
        # print("data=", data) 
        print("args", args)
        # parser = plot.Plot.default_parser()
        # args = parser.parse_args(*args)

        query = " mptcpstream == %d " % args.mptcpstream
        # filter to only account for one direction (departure or arrival)
        for ip in args.sender_ips:
            query += " or ip.src == %s " % ip
        # dat = data[data.mptcpstream == args.mptcpstream]
        log.debug("Running query %s" % query)
        dat = data.query(query)

        # TODO try replacing with dat.empty
        if not len(dat.index):
            print("no packet matching query %s" % query)
            return

        dat.sort_values("dsn", ascending=True, inplace=True)
       
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

        args.out = os.path.join(os.getcwd(), args.out)
        print("Saving into %s" % (args.out))
        fig.savefig(args.out)
        return True



# TODO use a handler as in http://matplotlib.org/1.3.1/users/legend_guide.html
# my_handler = HandlerLine2D(numpoints=1)
# legend(handler_map={Line2D:my_handler})
class PerSubflowTimeVsDsn(plot.Plot):

    def _generate_plot(self, data, args):
        # print("data=", data) 
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
        # TODO field should be DSN
        # field = "dsn"
        # field = "dss_dsn"
        field = "dss_ssn"


        axes = fig.gca()
        # df.plot(kind='line') is equivalent to df.plot.line() since panda 0.17
        # should return axes : matplotlib.AxesSubplot
        # returns a panda.Series for a line :s
        pplot = tcpstreams[field].plot.line(
            # gca = get current axes (Axes), create one if necessary
            ax=axes,
            # x=tcpstreams["reltime"],
            # x="Relative time", # ne marche pas
            # title="Data Sequence Numbers over subflows", 
            # use_index=False,
            legend=True,
            # style="-o",
            grid=True,
            # xticks=tcpstreams["reltime"],
            # rotation for ticks
            # rot=45, 
            # lw=3
        )

        # TODO should be able to set the direction
        # print(dir(axes))
        axes.set_xlabel("Time")
        axes.set_ylabel("DSN")
        # print("toto", type(pplot))

        ###  Correct legend for the linux 4 subflow case
        #############################################################
        h, l = axes.get_legend_handles_labels()

        # axes.legend([h[0], h[2]], ["Subflow 1", "Subflow 2"])
        # axes.legend([h[0], h[1]], ["Subflow 1", "Subflow 2"])
        print(h, l)

        args.out = os.path.join(os.getcwd(), args.out)
        print("Saving into %s" % (args.out))
        fig.savefig(args.out)
        return True


class DSSOverTime(plot.Plot):
    """
    Draw small arrows based on length etc...
    """

    def __init__(self):
        # super(self, "dsn")
        pass

    # def _generate_plot(self, data, *args, **kwargs):
    def _generate_plot(self, data, args):
        # print("data=", data) 
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
        # field = "dsn"
        # field = "dss_dsn"
        field = "dss_ssn"
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

        # field = "dack"
        # pplot = tcpstreams[field].plot.line(
        #     # gca = get current axis
        #     ax=fig.gca(),
        #     # x=tcpstreams["reltime"],
        #     # x="Relative time", # ne marche pas
        #     # title="Data Sequence Numbers over subflows", 
        #     # use_index=False,
        #     # legend=True,
        #     style="-o",
        #     # grid=True,
        #     # xticks=tcpstreams["reltime"],
        #     # rotation for ticks
        #     # rot=45, 
        #     # lw=3
        # )

        # # patches1, labels1 = ax1.get_legend_handles_labels()
        # # ax.legend()
        # # print(dir(pplot))
        # # ax = pplot.axes[0].get_figure()
        # ax = fig.gca()
        # # print(dir(pplot))
        # # pplot.ax
        # ax.set_xlabel("Relative time")
        # # pplot.set_xlabel("Time")
        # ax.set_ylabel("DSN")
        # # fig = ax.get_figure()
        # # for axes in plot:
        # # print("Axis ", axes)
        # # fig = axes.get_figure()
        # # fig.savefig("/home/teto/test.png")
        # # fig = plot.get_figure()
        args.out = os.path.join(os.getcwd(), args.out)
        print("Saving into %s" % (args.out))
        fig.savefig(args.out)
        return True

