# -*- coding: utf-8 -*-
import mptcpanalyzer.plot as plot
import mptcpanalyzer as mp
import pandas as pd
import argparse
import matplotlib.pyplot as plt
from mptcpanalyzer import _receiver, _sender, PreprocessingActions
from mptcpanalyzer.statistics import mptcp_compute_throughput
from mptcpanalyzer.data import load_merged_streams_into_pandas
from mptcpanalyzer.parser import gen_pcap_parser, MpTcpAnalyzerParser
from mptcpanalyzer.debug import debug_dataframe
import collections
from typing import List
import logging

log = logging.getLogger(__name__)


def compute_goodput(df, averaging_window):
    raise NotImplemented("Please implement me")


def tput_parser(parser):
    parser.add_argument("--window", "-w", metavar="AVG_WINDOW", action="store",
        type=int, default=1,
        help="Averaging window (in seconds), for instance '1'"
    )
    # boxcar
    # triang
    # blackman
    # hamming
    # bartlett
    # parzen
    # bohman
    # blackmanharris
    # nuttall
    # barthann
    # kaiser (needs beta)
    # gaussian (needs std)
    # general_gaussian (needs power, width)
    # slepian (needs width).

    parser.add_argument("--window-type", action="store",
        # as listed in pandas
        choices= [ "boxcar", "triang", "blackman", "hamming", "bartlett", "parzen", "bohman"],
        default="boxcar",
        help="Windowing algorithm"
    )
    parser.add_argument("--goodput", action="store_true",
        default=False,
        help="Drops retransmission from computation"
    )
    return parser

def compute_throughput(seq_col, time_col, averaging_window) -> pd.DataFrame:
    """
    Args:
        averaging_window:
        time_col:  time column
        seq_col:  sequence column


    Converts time series into pandas format so that we can use the rolling window
    algorithm on it

    Adds following columns to the dataframe:
    - tput
    - dt_abstime: abstime but in datetime format so that one can apply "rolling" features

    wireshark example can be found in:
    ui/qt/tcp_stream_dialog.cpp: void TCPStreamDialog::fillThroughput()

    // Throughput Graph - rate of sent bytes
    // Goodput Graph - rate of ACKed bytes

    todo should make it work with dack/ack
    problem is we don't support sack :'(
    """
    # df.rolling(on="bytes")
    # we can use mptcp.ack
    # we can use tcp.ack that are relative
    # rolling window can use offset

    # assert (field == "tcpack" or field "dack")

    # pdtime = "dt_abstime"
    # TODO newdf Dataframe
    pdtime = pd.to_datetime(time_col, unit="s")

    # print(pdtime)

    # import re
    # string1 = averaging_window
    # I should retreive the unit afterwards
    # averaging_window_int = int(re.search(r'\d+', string1).group())

    averaging_window_int = averaging_window
    averaging_window_str = "%ss" % averaging_window
    # TODO use it as index to use the rolling ?
    def _compute_tput(x, ):
        """
        Not an exact one, does not account for TCP sack for instance
        """
        # print("%s:\n%r" % (type(x), x))
        # so now it gets a series

        # print("max %f min %f average %d" % (x.max(), x.min(), averaging_window_int))
        return (x.max() - x.min())/averaging_window_int

    # TODO test
    newdf = pd.DataFrame(data={"seq": seq_col},) # index=pdtime)
    newdf["seq"] = seq_col
    newdf.set_index(pdtime, drop=False, inplace=True)

    # print("newdf")
    # print(newdf)

    log.debug("Rolling over an interval of %s" % averaging_window_str)
    temp = newdf["seq"].astype("float64").rolling(
        # 3,
        # can be a number of an offset if index is datetime
        window=averaging_window_str,
        # parameters of interest too
        # min_periods=
        # on="tcpack",
        # closed="right",
        # center=True
    )

    newdf["tput"] = temp.apply(
        _compute_tput,
        # pass the data as a Serie rather than a numpy array
        raw=False,
        # generates an unexpected keyword error ??!!!
        # convert_dtype=False,
    )

    return newdf


def plot_tput(fig, *args, label=None):
    """
    Expects a dataframe with a certain format
    todo how to deal with legends
    Args:

    TODO generate legends ourselves
    """
    axes = fig.gca()

    log.debug("Plotting tput")

    tput_df = compute_throughput(*args)
    # print("tput_df")
    # print(tput_df)
    tput_df.plot.line(
        ax=axes,
        legend=True,
        # TODO should depend from
        # x="dt_abstime",
        y="tput",
        # y="gput",
        label=label
        # "Xput towards %s" % "FIX", # seems to be a bug
    )


class TcpThroughput(plot.Matplotlib):
    """
    Plot Tcp throughput
    Mptcp throughput equals the sum of subflow contributions
    """
    def __init__(self, *args, **kwargs):
        super().__init__(
                *args,
                title="TCP throughput",
                x_label="Time (s)",
                **kwargs
            )

    def default_parser(self, *args, **kwargs):

        parser = MpTcpAnalyzerParser(
            description="Helps plotting TCP throughput"
        )
        parser.epilog = """
            > plot tcp_tput examples/client_2_redundant.pcapng 0 examples/server_2_redundant.pcapng 0 3
        """
        res = super().default_parser(
            *args, parents=[parser],
            **kwargs
        )

        pcaps = {
            "pcap": PreprocessingActions.Preload | PreprocessingActions.FilterTcpStream
        }
        final = gen_pcap_parser(pcaps, parents=[res], direction=True)

        final = tput_parser(final)
        return final

    def plot(self, pcap, pcapstream, **kwargs):
        """
        getcallargs
        """

        fig = plt.figure()
        axes = fig.gca()

        df = pcap
        window = kwargs.get("window")
        destinations = kwargs.get("pcap_destinations")

        print("Destinations", destinations)


        con = df.tcp.connection(pcapstream)
        df = con.fill_dest(df)

        debug_dataframe(df, "plotting throughput" )
        for dest, subdf in df.groupby("tcpdest"):
            if dest not in destinations:
                log.debug("Ignoring destination %s" % dest)
                continue

            log.debug("Plotting destination %s" % dest)

            label_fmt = "TCP stream {stream}"
            if len(destinations) >= 2:
                label_fmt = label_fmt + " towards TCP {dest}"

            plot_tput(
                fig, subdf["tcpack"], subdf["abstime"],
                window,
                label=label_fmt.format(stream=pcapstream, dest=dest)
            )

        # TODO plot on one y the throughput; on the other the goodput
        self.y_label = "Throughput (bytes/second)"

        # TODO pass con towards a direction ?
        self.title = "TCP Throughput (Average window of %s) for con:\n%s" % (window, con)
        # self.title = "TCP Throughput (Average window of %s)" % window

        # handles, labels = axes.get_legend_handles_labels()

        # # Generate "subflow X" labels
        # # location: 3 => bottom left, 4 => bottom right
        # axes.legend(
        #     handles,
        #     ["%s for Subflow %d" % (field, x) for x, _ in enumerate(labels)],
        #     loc=4
        # )

        return fig


class SubflowThroughput(TcpThroughput):
    """
    Plot subflow throughput
    Mptcp throughput equals the sum of subflow contributions
    """
    # def __init__(self, *args, **kwargs):
    #     super().__init__(
    #             *args,
    #             title="TCP throughput",
    #             x_label="Time (s)",
    #             **kwargs
    #         )


    # TODO add window / destinations ?
    # dat, destinations,
    def plot_dest(self, pcap, pcapstream, dest : mp.ConnectionRoles, **kwargs):
        pass


class MptcpThroughput(plot.Matplotlib):
    """
    Plots aggregated tput
    """
    def __init__(self, *args, **kwargs):
        super().__init__(
            *args,
            title="MPTCP throughput",
            x_label="Time (s)",
            y_label="Throughput (bytes/s)",
            **kwargs
        )

    def default_parser(self, *args, **kwargs):

        parser = MpTcpAnalyzerParser(
            description="Helps plotting Data sequence numbers"
        )
        parser.epilog = """
            plot mptcp_tput examples/client_2_redundant.pcapng 0 examples/server_2_redundant.pcapng 0 3
        """
        # return parser
        res = super().default_parser(
            *args, parents=[parser],
            **kwargs
        )

        pcaps = {
            "pcap": PreprocessingActions.Preload | PreprocessingActions.FilterMpTcpStream
        }
        final = gen_pcap_parser(pcaps, parents=[res], direction=True)

        # passed window 3 is not compatible with a datetimelike index
        final = tput_parser(final)
        return final


    def plot(self, pcap, pcapstream, window, **kwargs):
        """
        TODO for now only plots subflows
        plots the mptcp aggregate or mptcpack instead ?
        """
        fig = plt.figure()
        axes = fig.gca()

        df = pcap
        destinations = kwargs.get("pcap_destinations")

        con = df.mptcp.connection(pcapstream)
        df = con.fill_dest(df)

        if len(destinations) == 1:
            suffix = " towards MPTCP %s" % (destinations[0].to_string())
            self.title = self.title + suffix

        ### plot subflows first...
        ##################################################
        fields = ["tcpstream", "tcpdest", "mptcpdest"]
        for idx, subdf in df.groupby(fields, sort=False):
            tcpstream, tcpdest, mptcpdest = idx
            if mptcpdest not in destinations:
                log.debug("Ignoring MPTCP destination %s" % tcpdest)
                continue

            log.debug("Plotting tcp destination %s" % tcpdest)

            label_fmt="Subflow {tcpstream}"
            if len(destinations) >= 2:
                label_fmt = label_fmt + " towards MPTCP {mptcpdest}"

            # basically the same as for tcp
            plot_tput(
                fig, subdf["tcpack"], subdf["abstime"], window,
                label=label_fmt.format(tcpstream=tcpstream, mptcpdest=mp.ConnectionRoles(mptcpdest).to_string())
            )

        ### then plots MPTCP level throughput
        ##################################################
        for mptcpdest, subdf in df.groupby("mptcpdest"):
            # tcpdest, tcpstream, mptcpdest = idx
            if mptcpdest not in destinations:
                log.debug("Ignoring destination %s" % mptcpdest)
                continue

            log.debug("Plotting mptcp destination %s" % mptcpdest)

            plot_tput(
                fig, subdf["dack"], subdf["abstime"], window,
                label="MPTCP towards %s" % mptcpdest
            )

        return fig

