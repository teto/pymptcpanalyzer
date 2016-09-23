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

    .. warn: There is a bug in Pandas that prevents from plotting raw DSNs as uint64 see https://github.com/pymain/pandas/issues/11440


    Attributes:
        title (str): title to give to the plot
        enabel_preprocessing (bool): Automatically filters dataframes beforehand
    """

    def __init__(self, title: str = None, preprocess_dataframes: bool=False, *args, **kwargs):
        """
        Args:
            title (str): Plot title
        """
        self.title = title
        self.enable_preprocessing = preprocess_dataframes

    def default_parser(self, available_dataframe : bool,
            required_nb_of_dataframes : int = 1,
            mptcpstream: bool = False,
            direction: bool = False, filter_subflows: bool = True,
            dst_host : bool=False):
        """
        Generates a parser with common options.
        This parser can be completed or overridden by its children.

        Args:
            mptcpstream: to accept an mptcp.stream id
            available_dataframe: True if a pcap was preloaded at start
            direction: Enable filtering the stream depending if the packets
            were sent towards the MPTCP client or the MPTCP server
            filter_subflows: Allow to hide some subflows from the plot

        Return:
            An argparse.ArgumentParser

        """
        parser = argparse.ArgumentParser(
            description=self.__doc__)
        #'Generate MPTCP stats & plots'

        # how many pcaps shall we load ?
        count = required_nb_of_dataframes - (1 if available_dataframe else 0)
        for i in range(0, count):

            parser.add_argument("pcap",  action="append",
                    metavar="pcap%d" % i,
                    type=str,
                    help='Pcap file (or its associated csv)')

        if mptcpstream:
            parser.add_argument('mptcpstream', action="store", type=int,
                    help='mptcp.stream id, you may find using the "list_connections" command'
            )

            if direction:
                # a bit hackish: we want the object to be of type class
                # but we want to display the user readable version
                # so we subclass list to convert the Enum to str value first.
                class CustomDestinationChoices(list):
                    def __contains__(self, other):
                        return super().__contains__(other.value)
                parser.add_argument('destination', action="store",
                        choices=CustomDestinationChoices([e.value for e in mp.Destination]),
                        type=lambda x: mp.Destination(x),
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

    @abc.abstractmethod
    def plot(self, rawdataframes, **kwargs):
        """
        This is the command

        Args:
            rawdataframes: A single pandas.DataFrame or a list of them depending on your plot.
            The dataframe is unfiltered thus in most cases, you would need to preprocess it with
            :member:`.preprocess`

        """
        pass

    def preprocess(self, rawdf, mptcpstream=None, skipped_subflows=[], **opt):
        """
        Can filter a single dataframe beforehand 
        (hence call it several times for several dataframes).

        Args:
            rawdf: Raw dataframe
            opt: Should be the expanded result of argparse
            mptcpstream: Filters the dataframe so as to keep only the packets related to mptcp.stream == mptcpstream
            skipped_subflows: list of skipped subflows

        This baseclass can filter on:

        - mptcpstream
        - destination (mptcpstream required)
        - skipped_subflows

        Returns:
            Filtered dataframe
        """
        log.debug("Preprocessing dataframe")
        queries = []
        dataframe = rawdf

        if mptcpstream is not None:
            queries.append("mptcpstream==%d" % mptcpstream )
            if opt.get('destination', False):
                # Generate a filter for the connection
                con = MpTcpConnection.build_from_dataframe(dataframe, mptcpstream)
                q = con.generate_direction_query(opt.get('destination'))
                queries.append(q)

        for skipped_subflow in skipped_subflows:
            queries.append(" tcpstream!=%d " % skipped_subflow)

        query = " and ".join(queries)

        # throws when querying with an empty query
        if len(query) > 0:
            log.info("Running query: %s" % query)
            dataframe = rawdf.query(query)

        if not len(dataframe.index):
            raise Exception("Empty dataframe after running query [%s]" % query)

        return dataframe


    def postprocess(self, v, **opt):
        """
        Args:
            v is the value returned by :class:`.run`

        """
        pass

    def run(self, rawdataframes, *pargs, **kwargs):
        """
        This function automatically filters the dataset according to the
        options enabled

        Args:
            dataframes: an array of dataframes loaded by the main program
            pargs: Array of parameters forwarded to argparse parser.
        """
        dataframes = rawdataframes
        if self.enable_preprocessing:
            dataframes = [self.preprocess(df, **kwargs) for df in dataframes]

        # if only one element, pass it directly instead of a list
        # if len(dataframes) == 1:
        #     dataframes = dataframes[0]
        self.plot(dataframes[0] if len(dataframes) == 1 else dataframes)



    def display(self, filename):
        """
        Opens filename in your usual picture viewer
        Relies on xdg-open by default so set your mimetypes correctly !
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


    def postprocess(self, v, display: bool=False, out=None, **opt):
        """

        Args:
            v: Value returned by `run` member, its type may depend on the plot
            display (bool): Wether we should display the resulting plot
            out: if the file was saved to a file

        """
        # self.title = args.title if args.title else self.title
        if opt.get('title', self.title):
            v.suptitle(self.title, fontsize=12)
        
        if out:
            self.savefig(v, out)

        if display:
            self.display(out)

        super().postprocess(v, **opt)


    def run(self, dataframes, styles, *pargs, **kwargs):
        """
        user should override plot() -> TODO plot

        Args:
            dataframes: a list of
            styles: a list of styles

        Returns:
            A matplotlib figure
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
            fig = self.plot(dataframes, **kwargs)

        return fig

    @staticmethod
    def savefig(fig, filename, **kwargs):
        """
        Save a figure to a file

        Args:
            kwargs: Forwarded to :member:`matplotlib.Figure.savefig`. 
            You can set *dpi* for instance  (80 by default ?)
        """
        filename = os.path.join(os.getcwd(), filename)
        print("Saving into %s" % (filename))
        # dpi can be set from resource config
        fig.savefig(filename, **kwargs)

