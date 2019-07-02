import argparse
import os
import tempfile
import matplotlib.pyplot as plt
import matplotlib as mpl
import mptcpanalyzer as mp
from mptcpanalyzer import PreprocessingActions
from mptcpanalyzer.parser import gen_pcap_parser
import pandas as pd
from mptcpanalyzer.data import (load_into_pandas, load_merged_streams_into_pandas)
from mptcpanalyzer.tshark import TsharkConfig
import enum
from mptcpanalyzer.connection import MpTcpConnection, TcpConnection
from mptcpanalyzer.parser import MpTcpAnalyzerParser
from typing import List, Tuple, Collection, Dict, Any
from cmd2 import argparse_completer
import copy
import abc
import logging
import inspect
from dataclasses import dataclass

log = logging.getLogger(__name__)


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
    # title: str
    # x_label: str
    # y_label: str

    def __init__(
        self,
        exporter: TsharkConfig,
        title_fmt: str = None,
        x_label: str = None,
        y_label: str = None,
        *args, **kwargs
    ) -> None:
        """
        Args:
            title (str): Plot title
        """
        self.title_fmt = title_fmt
        """ f-string that can be formatted later on """
        # python shallow copies objects by default
        self.tshark_config = copy.deepcopy(exporter)
        # self.tshark_config.read_filter = protocol + " and not icmp"
        self.x_label = x_label
        self.y_label = y_label


    def default_parser(
        self,
        parents=None,
        # input_pcaps: List[Tuple[str, PreprocessingActions]],
        **kwargs
    ) -> MpTcpAnalyzerParser:
        """
        Generates a parser with common options.
        This parser can be completed or overridden by its children.

        Args:
            mptcpstream: to accept an mptcp.stream id
            available_dataframe: True if a pcap was preloaded at start
            direction: Enable filtering the stream depending if the packets
            were sent towards the MPTCP client or the MPTCP server
            skip_subflows: Allow to hide some subflows from the plot

        """
        if parents is None:
            # as per the nice comment https://github.com/teto/mptcpanalyzer/issues/10
            parents = []
        parser = MpTcpAnalyzerParser(
            parents=parents,
            add_help=(parents == []),
        )

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
    def plot(self, **kwargs) -> Tuple[Dict[str, Any], Any]:
        """
        This is the command

        Args:
            rawdataframes: A single pandas.DataFrame or a list of them depending on your plot.
            The dataframe is unfiltered thus in most cases, you would need to preprocess it with
            :member:`.preprocess`

        """
        pass

    def postprocess(self, v, **opt):
        """
        Args:
            v: the value returned by :class:`.run`
        """
        pass

    # TODO remove
    def preprocess(self, **kwargs) -> Collection[pd.DataFrame]:
        """
        Must return the dataframes used by plot
        kwargs should contain arguments with the pcap names passed to self.input_pcaps
        """
        hidden_dataframes = kwargs.get("_dataframes", {})
        # for pcap_name, actions in dataframes:
        #     log.info("pcap_name=%s value=%r" % (pcap_name, kwargs.get(pcap_name)))

        return hidden_dataframes

    @abc.abstractmethod
    def run(self, **kwargs):
        """
        This function automatically filters the dataset according to the
        options enabled

        Args:
            rawdataframes: an array of dataframes loaded by the main program
            kwargs: parameters forwarded from the argparse parser return by :method:`.default_parser`.

        Returns:
            None: has to be subclassed as the return value is used in :member:`.postprocess`
        """
        pass
        # dataframes = rawdataframes

        # dataframes = dataframes[0] if len(dataframes) == 1 else dataframes,
        # self.plot(dataframes, **kwargs)

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
        parser.add_argument(
            '--style', dest="styles", action="append", default=[],
            help=inspect.cleandoc("""
                List matplotlib styles, you can specify several styles
                via several --style items.
                The style should be either an absolute path or the
                name of a style present in the folder
                $XDG_CONFIG_HOME/matplotlib/stylelib.
                (matplotlib will merge it with $XDG_CONFIG_HOME/matplotlib/matplotlibrc).
                """))
        return parser

    @abc.abstractmethod
    def plot(self, **kwargs) -> mpl.figure.Figure:
        pass


    def postprocess(self, plot_data, display: bool = False, out=None, **kwargs):  # type: ignore
        """
        Args:
            plot_data: Value returned by `run` member, its type may depend on the plot
            display (bool): Wether we should display the resulting plot
            out: if the file was saved to a file

        """
        user_title = kwargs.get('title')

        if user_title:
            log.info("User passed title [%s]", user_title)

        title_fmt = user_title or self.title_fmt
        if title_fmt and title_fmt != "none":
            log.info("Setting plot title to %s", title_fmt)
            title = title_fmt.format()
            plot_data.suptitle(title)

        # TODO check it works without title
        axes = plot_data.gca()
        axes.set_xlabel(self.x_label)
        axes.set_ylabel(self.y_label)

        if out:
            self.savefig(plot_data, out)


        log.debug("plot_data %r" % plot_data)

        if display:
            if out is None:
                with tempfile.NamedTemporaryFile(delete=False) as tmpfile:
                    log.info("No output file set, using tempfile=%s", tmpfile)
                    r = self.savefig(plot_data, tmpfile.name)
                    log.debug("returned %r", r)
                    self.display(tmpfile.name)
            else:
                self.display(out)

        super().postprocess(plot_data, **kwargs)


    def run(self, styles=None, *pargs, **kwargs):
        """
        user should override plot() -> TODO plot

        Args:
            dataframes: a list of
            styles: a list of styles

        Returns:
            A matplotlib figure
        """
        log.debug("Using matplotlib styles: %s" % styles)

        if styles is None:
            styles = []

        with plt.style.context(styles):
            # print("dataframes", dataframes, "styles=", styles, " and kwargs=", kwargs)
            fig = self.plot(*pargs, styles=styles, **kwargs)
            assert fig, "'plot' method must return something"

        return fig

    @staticmethod
    def savefig(fig, filename, **kwargs):
        """
        Save a figure to a file

        Args:
            kwargs: Forwarded to :member:`matplotlib.Figure.savefig`.
            You can set *dpi* for instance  (80 by default ?)
        """
        log.info("Saving into %s", filename)
        # most settings (dpi for instance) can be set from resource config
        fig.savefig(filename, format="png", **kwargs)
        return filename
