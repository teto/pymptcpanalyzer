#!/usr/bin/env python
# -*- coding: utf-8 -*-
import argparse
import os
import tempfile
import matplotlib
import matplotlib.pyplot as plt
import collections
import mptcpanalyzer as mp
from mptcpanalyzer.data import load_into_pandas
from enum import Enum, IntEnum
from mptcpanalyzer.connection import MpTcpConnection
from typing import Iterable, List, Any, Tuple, Dict, Callable
import abc
import six
import logging

log = logging.getLogger(__name__)

class PreprocessingActions(IntEnum):
    """
    Used to set bitfields

    TODO: skipSubflows ? filterDirection ?
    """
    DoNothing = 0
    Preload = 1
    FilterMpTcpStream = 2


def gen_ip_filter(mptcpstream, ipsrc=None, ipdst=None):
    """
    filter mainset from ips
    filter to only account for one direction (departure or arrival)
    """
    # if mptcpstream:
    query = " mptcpstream == %d " % mptcpstream

    if ipsrc:
        query += " and ("
        query_ipdst = map(lambda x: "ipsrc == '%s'" % x, ipsrc)
        query += ' or '.join(query_ipdst)
        query += ")"

    if ipdst:
        query += " and ("
        query_ipdst = map(lambda x: "ipdst == '%s'" % x, ipdst)
        query += ' or '.join(query_ipdst)
        query += ")"

    return query


# @six.add_metaclass(abc.ABCMeta)
class Plot:
    """
    This is a helper class designed to provide basic functionalities so that
    it becomes easier to create new plots.

    See http://docs.openstack.org/developer/stevedore/tutorial/creating_plugins.html

    .. warn: A bug in Pandas prevents from plotting raw DSNs as uint64
            see https://github.com/pymain/pandas/issues/11440

    Attributes:
        title (str): title to give to the plot
        enabel_preprocessing (bool): Automatically filters dataframes beforehand
    """

    def __init__(
        self,
        exporter : 'TsharkConfig',
        # we want an ordered dict but type hinting OrderedDict is not in python3 batteries
        # TypedDict is in mypy 0.540
        input_pcaps: List[Tuple[str, PreprocessingActions]],
        title: str = None,
        *args, **kwargs
    ) -> None:
        """
        Args:
            title (str): Plot title
        """
        self.title = title
        self.input_pcaps = input_pcaps
        self.tshark_config = exporter

    @property
    def cache(self):
        return self.main.cache

    def default_parser(
        self,
        # TODO remove two followings ?
        parent_parsers=[],
        # available_dataframe: bool,
        # required_inputs: List[str] = ["pcap"],
        mptcpstream: bool = False,
        direction: bool = False, skip_subflows: bool = True,
        dst_host: bool=False
    ):
        """
        Generates a parser with common options.
        This parser can be completed or overridden by its children.

        Args:
            mptcpstream: to accept an mptcp.stream id
            available_dataframe: True if a pcap was preloaded at start
            direction: Enable filtering the stream depending if the packets
            were sent towards the MPTCP client or the MPTCP server
            skip_subflows: Allow to hide some subflows from the plot

        Return:
            An argparse.ArgumentParser

        """
        parser = argparse.ArgumentParser(
            parents=parent_parsers,
            add_help=False if len(parent_parsers) else True,
        )

        # how many pcaps shall we load ?
        # count = required_nb_of_dataframes - (1 if available_dataframe else 0)
        # for i in range(0, count):

        # for name in required_inputs:
        print("preload = ", type(self.input_pcaps), self.input_pcaps)
        for name, bitfield in self.input_pcaps:
            parser.add_argument(
                name,
                # action="append",
                action="store",
                # metavar="pcap%d" % i,
                type=str,
                help='Pcap file (or its associated csv)'
            )

            # if bitfield & PreprocessingActions.FilterMpTcpStream:
            #     parser.add_argument(
            #         'mptcpstream', action="store", type=int,
            #         help='mptcp.stream id, you may find using the "list_connections" command'
            #     )

        if mptcpstream:
            parser.add_argument(
                'mptcpstream', action="store", type=int,
                help='mptcp.stream id, you may find using the'
                '"list_connections" command')

            if direction:
                # a bit hackish: we want the object to be of type class
                # but we want to display the user readable version
                # so we subclass list to convert the Enum to str value first.
                class CustomDestinationChoices(list):
                    def __contains__(self, other):
                        return super().__contains__(other.value)
                parser.add_argument(
                    'destination', action="store",
                    choices=CustomDestinationChoices([e.value for e in mp.Destination]),
                    type=lambda x: mp.Destination(x),
                    help='Filter flows according to their direction'
                    '(towards the client or the server)'
                    'Depends on mptcpstream')

        if dst_host:
            parser.add_argument(
                'ipdst_host', action="store",
                help='Filter flows according to the destination hostnames')

        if skip_subflows:
            parser.add_argument(
                '--skip', dest="skipped_subflows", type=int,
                action="append", default=[],
                help=("You can type here the tcp.stream of a subflow "
                    "not to take into account (because"
                    "it was filtered by iptables or else)"))

        parser.add_argument('-o', '--out', action="store", default=None,
            help='Name of the output plot')
        parser.add_argument('--display', action="store_true",
            help='will display the generated plot (use xdg-open by default)')
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

    def filter_dataframe(
        self, rawdf, mptcpstream=None, skipped_subflows=[],
        destination: mp.Destination=None,
        extra_query: str =None, **kwargs
    ):
        """
        Can filter a single dataframe beforehand
        (hence call it several times for several dataframes).

        Feel free to inherit/override this class.

        Args:
            rawdf: Raw dataframe
            kwargs: expanded arguments returned by the parser
            destination: Filters packets depending on their :enum:`.Destination`
            mptcpstream: keep only the packets related to mptcp.stream == mptcpstream
            skipped_subflows: list of skipped subflows
            extra_query: Add some more filters to the pandas query

        This baseclass can filter on:

        - mptcpstream
        - destination (mptcpstream required)
        - skipped_subflows

        Returns:
            Filtered dataframe
        """
        log.debug("Preprocessing dataframe with extra args %s" % kwargs)
        queries = []
        dataframe = rawdf

        if mptcpstream is not None:
            log.debug("Filtering mptcpstream")
            queries.append("mptcpstream==%d" % mptcpstream)
            if destination is not None:
                log.debug("Filtering destination")
                # Generate a filter for the connection
                con = MpTcpConnection.build_from_dataframe(dataframe, mptcpstream)
                q = con.generate_direction_query(destination)
                queries.append(q)

        for skipped_subflow in skipped_subflows:
            log.debug("Skipping subflow %d" % skipped_subflow)
            queries.append(" tcpstream!=%d " % skipped_subflow)

        if extra_query:
            log.debug("Appending extra_query=%s" % extra_query)
            queries.append(extra_query)

        query = " and ".join(queries)

        # throws when querying with an empty query
        if len(query) > 0:
            log.info("Running query:\n%s\n" % query)
            dataframe = rawdf.query(query)

        # TODO remove should be left to plot df.empty
        # if not len(dataframe.index):
        #     raise Exception("Empty dataframe after running query [%s]" % query)
        return dataframe

    def postprocess(self, v, **opt):
        """
        Args:
            v: the value returned by :class:`.run`
        """
        pass

    def preprocess(self, main, **kwargs):
        """
        Must return the dataframes used by plot
        """
        assert main, "Need reference to MpTcpAnalyzer"
        dataframes = []
        for pcap_name, action in self.input_pcaps:
            print("pcap_name=", pcap_name, "value=", kwargs.get(pcap_name))
            if action >= PreprocessingActions.Preload:
                df = load_into_pandas(kwargs.get(pcap_name), self.tshark_config)
                dataframes.append(df)

        # dataframes = [self.filter_dataframe(df, **kwargs) for df in dataframes]
        return dataframes

    def run(self, rawdataframes, **kwargs):
        """
        This function automatically filters the dataset according to the
        options enabled

        Args:
            rawdataframes: an array of dataframes loaded by the main program
            kwargs: parameters forwarded from the argparse parser return by :method:`.default_parser`.

        Returns:
            None: has to be subclassed as the return value is used in :member:`.postprocess`
        """
        dataframes = rawdataframes

        # if only one element, pass it directly instead of a list
        # if len(dataframes) == 1:
        #     dataframes = dataframes[0]
        dataframes = dataframes[0] if len(dataframes) == 1 else dataframes,
        self.plot(dataframes, **kwargs)

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

    Relying on matplotlib plots allow for more customizations via the use of `style sheets
    <http://matplotlib.org/users/style_sheets.html>`_

    For instance to
    http://matplotlib.org/users/whats_new.html#added-axes-prop-cycle-key-to-rcparams

    """


    def __init__(self, *args, **kwargs):
        # print(args)
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
            if out is None:
                # TODO create a temporary file
                # print("%r")
                # v.imshow()
                with tempfile.NamedTemporaryFile() as tmpfile:
                    print("tempfile=", tmpfile)
                    print("\n=")
                    r = self.savefig(v, tmpfile.name)
                    print("returned", r)
                    self.display(tmpfile.name)
            else:
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
        # with plt.style.context(args.styles):
        # setup styles if any
        log.debug("Using matplotlib styles: %s" % styles)

        if len(dataframes) == 1:
            dataframes = dataframes[0]

        # matplotlib.pyplot.style.use(args.styles)
        # ('dark_background')
        with plt.style.context(styles):
            print("dataframes", dataframes, "styles=", styles, " and kwargs=", kwargs)
            fig = self.plot(dataframes, styles=styles, **kwargs)

        return fig

    @staticmethod
    def savefig(fig, filename, **kwargs):
        """
        Save a figure to a file

        Args:
            kwargs: Forwarded to :member:`matplotlib.Figure.savefig`.
            You can set *dpi* for instance  (80 by default ?)
        """
        print("Saving into %s" % (filename))
        # filename = os.path.join(os.getcwd(), filename)
        # dpi can be set from resource config
# , the value of the rc parameter savefig.format
        fig.savefig(filename, format="png", **kwargs)
        return filename
