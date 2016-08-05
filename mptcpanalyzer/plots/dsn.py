#!/usr/bin/env python
# -*- coding: utf-8 -*-

import mptcpanalyzer.plot as plot
import mptcpanalyzer as mp
import pandas as pd
import logging
import matplotlib.pyplot as plt
import os
from mptcpanalyzer import fields_v2

log = logging.getLogger(__name__)

# TODO use a handler as in http://matplotlib.org/1.3.1/users/legend_guide.html
# my_handler = HandlerLine2D(numpoints=1)
# legend(handler_map={Line2D:my_handler})
class PerSubflowTimeVsX(plot.Matplotlib):
    """
    Plot one or several mptcp attributes (dsn, dss, etc...) on a same plot.
    This should be the most straightforward plot.

    For now it relies on the profile host file being 
    """
    mptcp_attributes = dict((x.name, x.label) for x in fields_v2() if x.label)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def default_parser(self, *args, **kwargs):
        parser = super().default_parser(mptcpstream=True, direction=False, dst_host=True)
        # parser.add_argument('field', choices=self.mptcp_attributes, nargs="+", help="")
        parser.add_argument('field', choices=self.mptcp_attributes.keys(),
                help="Choose an mptcp attribute to plot")
        parser.add_argument('--skip', dest="skipped_subflows", type=int, action="append", default=[],
                help=("You can type here the tcp.stream of a subflow not to take into account (because"
                "it was filtered by iptables or else)"))
        return parser

    def _generate_plot(self, main, args):

        data = main.data
        dat = data[(data.mptcpstream == args.mptcpstream)] 
        if not len(dat.index):
            print("no packet matching mptcp.stream %d" % args.mptcpstream)
            return

        print( type(args.__dict__))
        for name, val in args.__dict__.items():
            print("name=",name)
        dat = self.filter_ds(dat, ipdst_host=args.ipdst_host)

        field = args.field

        fig = plt.figure()
        dat.set_index("reltime", inplace=True)
        tcpstreams = dat.groupby('tcpstream')
 
        print("%d streams in the MPTCP flow" % len(tcpstreams))
        print("Plotting field %s" % field)
        # field = "dss_ssn"

        # gca = get current axes (Axes), create one if necessary
        axes = fig.gca()
        
        # TODO load styles from config
        # styles = [
        #         "red_o",
        #         "blue",
        #         ]


        # print("available matplotlib styles", plt.style.available)
        # look into 'styles' list:
        # print(tcpstreams)
        # counter = 0
        # print( "len of ", len(styles), " to compare with " , len(tcpstreams))
        for idx, (streamid, ds) in enumerate(tcpstreams):
            if streamid in args.skipped_subflows:
                print("skipping tcp streamid ", streamid)
                continue

            # if counter < len(styles):
            #     print("counter=", counter)
            #     print("Using style=", styles[counter])

            #     plt.style.use( (styles[counter]))

            #     counter += 1
                #or
            # with plt.style.context(('dark_background')):
            pplot = ds[field].plot.line(
                ax=axes,
                # use_index=False,
                legend=False,
                grid=True,
            )

        # seems there is no easy way 
        # http://stackoverflow.com/questions/14178194/python-pandas-plotting-options-for-multiple-lines
        # styles1 = ['bs-','ro-','y^-']
        # pplot = tcpstreams.plot.scatter(
        #     x="abstime",
        #     y=field,
        #     ax=axes,
        #     # use_index=False,
        #     legend=False,
        #     marker="o",
        #     linestyle=None,
        #     grid=True,
        # )

        axes.set_xlabel("Time (s)")
        # TODO retrieve description from field (instead of 
        # axes.set_ylabel("Data Sequence Number")
        axes.set_ylabel(self.mptcp_attributes[field])

        handles, labels = axes.get_legend_handles_labels()

        # Generate "subflow X" labels
        # location: 3 => bottom left, 4 => bottom right
        axes.legend(handles, [ "%s for Subflow %d" % (field, x) for x, _ in enumerate(labels) ], loc=4)

        ###  Correct legend for the linux 4 subflow case
        #############################################################
        # axes.legend([h[0], h[2]], ["Subflow 1", "Subflow 2"])
        # axes.legend([h[0], h[1]], ["Subflow 1", "Subflow 2"])
        
        return fig


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

    def _generate_plot(self, main, args, **kwargs):
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
    TODO rename into interDSN ?
    In case traffic is biderctional we must filter on one direction only
    """

    available = [
        "dsn",
        "dack"
    ]
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def default_parser(self):
        parser = super().default_parser()
        # parser.add_argument("--x-subflows", action="store_true", dest="crosssubflows", help="Consider only cross-subflow arrivals")
        parser.add_argument("attribute", choices=self.available, help="interarrival between which numbers")
        parser.add_argument("sender_ips", nargs="+", 
                help="list sender ips here to filter the dataset")
        return parser

    def _generate_plot(self, main, args, **kwargs):
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



class DssLengthHistogram(plot.Matplotlib):
    """
    Plots histogram 
    """

    def __init__(self):
        super().__init__(title="DSS Length")

    def _generate_plot(self, main, args):
        data = main.data
        dat = data[data.mptcpstream == args.mptcpstream]
        if not len(dat.index):
            print("no packet matching mptcp.stream %d" % args.mptcpstream)
            return

        fig = plt.figure()
        axes = fig.gca()
        dat.set_index("reltime", inplace=True)
        # tcpstreams = dat.groupby('tcpstream')
        field = "dss_length"
        pplot = dat[field].plot.hist(
            ax=axes,
            legend=True,
            grid=True,
        )
        return fig
    
class DSSOverTime(plot.Matplotlib):
    """
    WIP
    Draw small arrows with dsn as origin, and a *dss_length* length etc...
    """

    def __init__(self):
        # super(self, "dsn")
        pass

    def default_parser(self, *args, **kwargs):
        return super().default_parser(mptcpstream=True, *args, **kwargs)

    def _generate_plot(self, main, args):

        data = main.data
        dat = data[data.mptcpstream == args.mptcpstream]
        if not len(dat.index):
            print("no packet matching mptcp.stream %d" % args.mptcpstream)
            return

        
        dat = data[dat.dss_dsn > 0]
        print("len=" , len(dat))

# apparemment le mieux c'est ca 
# http://matplotlib.org/api/pyplot_api.html#matplotlib.pyplot.quiver
# plt.quiver( dat.reltime, dat.dss_dsn, [0]* len(dat.dss_dsn) ,  dat.dss_length, scale_units="xy", scale=1, angles="xy",)
        fig = plt.figure()
        axes = fig.gca()
        # dat.set_index("reltime", inplace=True)

        # tcpstreams = dat.groupby('tcpstream')
        # field = "dss_ssn"
        
        # pplot = tcpstreams[field].plot.line(
        #     ax=axes,
        #     legend=True,
        #     grid=True,
        # )

        # quiver(X, Y, U, V, **kw)

        print( dat.head())
        plt.quiver( 
                dat.reltime, # X
                dat.dsn, # Y
                [0]* len(dat.dss_dsn) ,
               dat.dss_length,
               scale_units="xy", scale=3, angles="xy",
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
        return fig

