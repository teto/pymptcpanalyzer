import argparse
import os
import tempfile
import matplotlib.pyplot as plt
import mptcpanalyzer as mp
import pandas as pd
from mptcpanalyzer.data import load_into_pandas, tcpdest_from_connections
from mptcpanalyzer.tshark import TsharkConfig
import enum
from mptcpanalyzer.connection import MpTcpConnection, TcpConnection
from typing import List, Tuple, Collection
from cmd2 import argparse_completer
import copy
import abc
import logging

log = logging.getLogger(__name__)


class PreprocessingActions(enum.Flag):
    """
    What to do with pcaps on the command line
    """
    DoNothing                = enum.auto()
    Preload                  = enum.auto()
    FilterTcpStream          = enum.auto()
    FilterMpTcpStream        = enum.auto()
    FilterStream             = FilterMpTcpStream | FilterTcpStream


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
        exporter : TsharkConfig,
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
        # python shallow copies objects by default
        self.tshark_config = copy.deepcopy(exporter)
        # self.tshark_config.read_filter = protocol + " and not icmp"
        

    def default_parser(
        self,
        parent_parsers=[],
        filterstream: bool = False,
        direction: bool = False, skip_subflows: bool = True,
        dst_host: bool=False,
    ) -> argparse_completer.ACArgumentParser:
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
        parser = argparse_completer.ACArgumentParser(
            parents=parent_parsers,
            add_help=False if len(parent_parsers) else True,
        )

        for name, bitfield in self.input_pcaps:

            def _metavar():
                pass

            load_pcap = parser.add_argument(name, action="store", type=str, help='Pcap file')
            setattr(load_pcap, argparse_completer.ACTION_ARG_CHOICES,
                ('path_complete', [False, False]))
            parser.add_argument("--clock-offset" + name, action="store", type=int,
                help='Offset compared to epoch (in nanoseconds)')

            if bitfield & PreprocessingActions.FilterStream:
                # difficult to change the varname here => change it everywhere
                protocol = "mptcp" if bitfield & PreprocessingActions.FilterMpTcpStream else "tcp"
                parser.add_argument(
                    protocol + 'stream', metavar= protocol + "stream", action="store", type=int,
                    help= protocol + '.stream id')

                if direction:
                    # this one is full of tricks: we want the object to be of the Enum type
                    # but we want to display the user readable version
                    # so we subclass list to convert the Enum to str value first.
                    parser.add_argument(
                        '--dest', metavar="destination", dest="destinations",
                        # see preprocess functions to see how destinations is handled when empty
                        default=None,
                        action="append",
                        choices=mp.CustomConnectionRolesChoices([e.name for e in mp.ConnectionRoles]),
                        # type parameter is a function/callable
                        type=lambda x: mp.ConnectionRoles.from_string(x),
                        # type=lambda x: mp.ConnectionRoles[x],
                        help='Filter flows according to their direction'
                        '(towards the client or the server)'
                        'Depends on mptcpstream')

                if protocol == "mptcp" and skip_subflows:
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
        self, rawdf, tcpstream=None, mptcpstream=None, skipped_subflows=[],
        destinations: list=None,
        extra_query: str=None, **kwargs
    ):
        """
        Can filter a single dataframe beforehand
        (hence call it several times for several dataframes).

        Feel free to inherit/override this class.

        Args:
            rawdf: Raw dataframe
            kwargs: expanded arguments returned by the parser
            destination: Filters packets depending on their :enum:`.ConnectionRoles`
            stream: keep only the packets related to mptcp.stream == mptcpstream
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
        print("tcp.stream", tcpstream, "mptcp:", mptcpstream)
        stream = tcpstream if tcpstream is not None else mptcpstream
        dataframe = rawdf

        for skipped_subflow in skipped_subflows:
            log.debug("Skipping subflow %d" % skipped_subflow)
            queries.append(" tcpstream!=%d " % skipped_subflow)

        if stream is not None:
            protocol = "mptcp" if mptcpstream is not None else "tcp"
            log.debug("Filtering %s stream #%d." % (protocol, stream))
            queries.append(protocol + "stream==%d" % stream)


            if protocol == "tcp":
                # generates the "tcpdest" component of the dataframe
                con2 = TcpConnection.build_from_dataframe(dataframe, stream)
                dataframe = tcpdest_from_connections(dataframe, con2)
                # trust plots to do the filtering
                # if destinations is not []:
                #     queries.append(protocol + "dest==%d" % stream)
            else:
                # todo shall do the same for mptcp destinations
                # if protocol == "mptcp":
                if destinations is not None:
                    raise Exception("destination filtering is not ready yet for mptcp")

                    log.debug("Filtering destination")
                    # Generate a filter for the connection
                    # con = MpTcpConnection.build_from_dataframe(dataframe, stream)
                    # q = con.generate_direction_query(destination)
                    # queries.append(q)

        if extra_query:
            log.debug("Appending extra_query=%s" % extra_query)
            queries.append(extra_query)

        query = " and ".join(queries)

        # throws when querying with an empty query
        if len(query) > 0:
            log.info("Running query:\n%s\n" % query)
            dataframe.query(query, inplace=True)

        return dataframe

    def postprocess(self, v, **opt):
        """
        Args:
            v: the value returned by :class:`.run`
        """
        pass

    def preprocess(self, **kwargs) -> Collection[ pd.DataFrame ]:
        """
        Must return the dataframes used by plot
        kwargs should contain arguments with the pcap names passed to self.input_pcaps
        """
        dataframes = []
        for pcap_name, actions in self.input_pcaps:
            log.info("pcap_name=%s value=%r" % (pcap_name, kwargs.get(pcap_name)))
            if actions & PreprocessingActions.Preload:
                filename = kwargs.get(pcap_name)
                df = load_into_pandas(filename, self.tshark_config,)
                if actions & PreprocessingActions.FilterStream:
                    df = self.filter_dataframe(df, **kwargs)

                dataframes.append(df)

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

        dataframes = dataframes[0] if len(dataframes) == 1 else dataframes,
        self.plot(dataframes, **kwargs)

    def display(self, filename):
        """
        Opens filename in your usual picture viewer
        Relies on xdg-open by default so set your mimetypes correctly !
        """
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
        if opt.get('title', self.title):
            v.suptitle(self.title, fontsize=12)

        if out:
            self.savefig(v, out)

        if display:
            if out is None:
                with tempfile.NamedTemporaryFile(delete=False) as tmpfile:
                    print("No output file set, using tempfile=%s" % tmpfile)
                    r = self.savefig(v, tmpfile.name)
                    log.debug("returned %r" % r)
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
        log.debug("Using matplotlib styles: %s" % styles)

        if len(dataframes) == 1:
            dataframes = dataframes[0]

        with plt.style.context(styles):
            # print("dataframes", dataframes, "styles=", styles, " and kwargs=", kwargs)
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
        logging.info("Saving into %s" % (filename))
        # most settings (dpi for instance) can be set from resource config
        fig.savefig(filename, format="png", **kwargs)
        return filename
