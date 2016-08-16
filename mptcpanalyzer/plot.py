#!/usr/bin/env python
# -*- coding: utf-8 -*-
import argparse
import os
import tempfile
# import core
import matplotlib
import matplotlib.pyplot as plt
import logging
import mptcpanalyzer as mp
from enum import Enum, IntEnum
from mptcpanalyzer.connection import MpTcpConnection

import abc
import six



log = logging.getLogger(__name__)




def gen_ip_filter(mptcpstream, ipsrc=None, ipdst=None):
    """
    filter mainset from ips
    filter to only account for one direction (departure or arrival)
    """
    # if mptcpstream:
    query = " mptcpstream == %d " % mptcpstream

    if ipsrc:
        query += " and ("
        query_ipdst = map( lambda x: "ipsrc == '%s'" % x, ipsrc)
        query += ' or '.join(query_ipdst)
        query += ")"

    if ipdst:
        query += " and ("
        query_ipdst = map( lambda x: "ipdst == '%s'" % x, ipdst)
        query += ' or '.join(query_ipdst)
        query += ")"

    return query

@six.add_metaclass(abc.ABCMeta)
class Plot:
    """
    This is a helper class designed to provide basic functionalities so that 
    it becomes easier to create new plots.

    See http://docs.openstack.org/developer/stevedore/tutorial/creating_plugins.html

    There is a bug in Pandas that prevents from plotting raw DSNs as uint64 see
    https://github.com/pymain/pandas/issues/11440
    """

    def __init__(self, needed_dataframes: int = 1, title : str = None, *args, **kwargs):
        #accept_preload : bool, filter_destination):
        """
        TODO pass a boolean to know if main.data should be preloaded or not
        """
        self.title = title
        """Title to give to the plot"""

    def default_parser(self, available_dataframe : bool,
            required_nb_of_dataframes : int = 1,
            mptcpstream: bool = False, 
            direction: bool = False, filter_subflows: bool = True,
            dst_host : bool=False):
        """
        Generates a default parser that can be then modified by the child class
        :param mptcpstream to accept an mptcp.stream id
        :param available_dataframe True if a pcap was preloaded
        :param direction Enable filtering the stream depending if the packets were sent
            towards the MPTCP client or the MPTCP server 
        :param filter_subflows Allow to hide some subflows from the plot
        """
        parser = argparse.ArgumentParser(description='Generate MPTCP stats & plots')

        count = required_nb_of_dataframes - (1 if available_dataframe else 0)
        print("COUNT=%d" % count)
        for i in range(0, required_nb_of_dataframes - (1 if available_dataframe else 0)):

            parser.add_argument("pcap",  action="append",
                    metavar="pcap%d" % i,
                    type=str,
                    help='Pcap file (or its associated csv)')

        if mptcpstream:
            parser.add_argument('mptcpstream', action="store", type=int, 
                    help='mptcp.stream id, you may find using the "list_connections" command'
            )

            if direction:
                parser.add_argument('destination', action="store", 
                        choices=[e.name for e in mp.Destination], 
                        help='Filter flows according to their direction'
                            '(towards the client or the server)'
                            'Depends on mptcpstream'
                )

        if dst_host:
            parser.add_argument('ipdst_host', action="store", 
                    help='Filter flows according to the destination hostnames')

        if filter_subflows:
            parser.add_argument('--skip', dest="skipped_subflows", type=int,
                    action="append", default=[],
                help=("You can type here the tcp.stream of a subflow "
                    "not to take into account (because"
                    "it was filtered by iptables or else)"))

        parser.add_argument('-o', '--out', action="store", default="output.png",
                help='Name of the output plot')
        parser.add_argument('--display', action="store_true", 
                help='will display the generated plot (use xdg-open by default)'
        )
        parser.add_argument('--title', action="store", type=str,
                help='Overrides the default plot title')
        parser.add_argument('--primary', action="store_true", 
                help="Copy to X clipboard, requires `xsel` to be installed")
        return parser

    # TODO move to MpTcpConnection
    # @staticmethod
    # def filter_ds(data, **kwargs):
    #     return mp.filter_df(data, **kwargs)


# TODO rename into plot
    @abc.abstractmethod
    def _generate_plot(self, dataframes, **kwargs):
        """
        This is the command 

        """
        pass

    @staticmethod
    def filter_df(df, mptcpstream = None, skip_subflows = []):
        """
        """

        queries = []
        if getattr(args, "mptcpstream", None):
            log.debug("Filtering mptcpstream")
            queries.append("mptcpstream == %d" % args.mptcpstream ) 

        for skipped_subflow in getattr(args, "skipped_subflows", []):
            queries.append(" tcpstream != %d " % skipped_subflow)

        query = " and ".join(queries)
        result = dataframes[0].query(query)

    
    def preprocess(self, dataframe, mptcpstream=None, skipped_subflows=[], **opt):
        """
        Can filter a dataframe beforehand

        :param opt Should be the expanded result of argparse
        This baseclass can filter on:
            - mptcpstream
            - destination (mptcpstream required)
            -skipped_subflows

        Returns updated dataframe
        """
        queries = []
        # if opt.get('mptcpstream', False):
        if mptcpstream:
            queries.append("mptcpstream == %d" % mptcpstream ) 
            if opt.get('destination', False):
                # Generate a filter for the connection
                con = MpTcpConnection.build_from_dataframe(dataframe, mptcpstream)
                q = con.generate_direction_query( opt.get('destination'))
                queries.append(q)

        # for skipped_subflow in opt.get("skipped_subflows", []):
        for skipped_subflow in skipped_subflows: 
            queries.append(" tcpstream != %d " % skipped_subflow)

        query = " and ".join(queries)



        # throws when querying with an empty query
        if len(query) > 0:
            log.info("Running query:\n%s" % query)
            dataframe = dataframe.query(query)

        if not len(dataframe.index):
            raise Exception("Empty dataframe after running query [%s]" % query)
            # print("no packet matching mptcp.stream %d"
            #     "(use 'lc' command to list connections)" % args.mptcpstream)
            # return

        return dataframe

    def postprocess(self, v, display=False, out="output.png", **opt):
        """
        :param v is the value returned by the plot
        """

        if display:
            self.display(out)


    def run(self, dataframes, *pargs, **kwargs):
        """
        This function automatically filters the dataset according to the 
        options enabled 
        :param dataframes an array of dataframes loaded by the main program
        :param cli_args Array of parameters forwarded to argparse parser.
        """
        # these options
        # if getattr(args, "direction"):
        print("cli_args:" % cli_args)

        # args, unknown_args = parser.parse_known_args(cli_args)
        # dargs = vars(args)
        # dataframes = [ self.preprocess(df, **dargs) for df in dataframes ]

        if len(dataframes) == 1:
            dataframes = dataframes[0]
        self._generate_plot(dataframes)



    def display(self, filename):
        """
        Opens filename in your usual picture viewer
        """
        log.debug("Displaying file")
        cmd = "xdg-open %s" % (filename)
        print(cmd)
        os.system(cmd)



class Matplotlib(Plot):
    """
    This class is specifically designed to generate matplotlib-based plots
    """
    

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def default_parser(self, *args, **kwargs):
        """
        Adds an option to specify the matplotlib styles to use
        """
        parser = super().default_parser(*args, **kwargs)
        parser.add_argument('--style', dest="styles", action="append", default=[],
            help=("List matplotlib styles, you can specify several styles "
                "via several --style items."
                "The style should be either an absolute path or the "
                "name of a style present in the folder "
                "$XDG_CONFIG_HOME/matplotlib/stylelib")
        )
        return parser


    def postprocess(self, v, **opt):
        """
        """
        # self.title = args.title if args.title else self.title
        if opt.get('title', self.title):
            fig.suptitle(self.title, fontsize=12)

        super().postprocess(v, **opt)
        # if args.out:
        #     self.savefig(fig, args.out)
        #     if args.primary:
        #         core.copy_to_x (args.out)

        # if args.display:
        #     # TODO show it from fig
        #     self.display(args.out)


    def run(self, dataframes, styles, *pargs, **kwargs):
        """
        user should override _generate_plot() -> TODO plot
        """
        # autofilter dataset if needed
        # for name, val in args.__dict__.items():
        #     if name in get_default_fields():
                #exporter
                # filter_ds()
        # check filetered dataset is not empty 
        # with plt.style.context(args.styles):
        # setup styles if any
        log.debug("Using styles: %s" % styles)

        if len(dataframes) == 1:
            dataframes = dataframes[0]

        # matplotlib.pyplot.style.use(args.styles)
        # ('dark_background')
        with plt.style.context(styles):
            fig = self._generate_plot(dataframes, **kwargs)

    @staticmethod
    def savefig(fig, filename):
        """
        Save a figure to a file
        """
        filename = os.path.join(os.getcwd(), filename)
        # logger.info
        print("Saving into %s" % (filename))
        fig.savefig(filename)

