# -*- coding: utf-8 -*-
import mptcpanalyzer.plot as plot
import mptcpanalyzer as mp
from mptcpanalyzer import TRACE
import pandas as pd
import argparse
import matplotlib.pyplot as plt
from mptcpanalyzer import _receiver, _sender, PreprocessingActions
from mptcpanalyzer.statistics import mptcp_compute_throughput
from mptcpanalyzer.data import load_merged_streams_into_pandas
from mptcpanalyzer.parser import gen_pcap_parser, MpTcpAnalyzerParser
from mptcpanalyzer.debug import debug_dataframe
from functools import partial
import collections
from typing import List
import logging

log = logging.getLogger(__name__)


def tput_parser(parser):
    parser.add_argument("--window", "-w", metavar="AVG_WINDOW", action="store",
        type=int, default=1,
        help="Averaging window (in seconds), for instance '1'")

    parser.add_argument("--window-type", action="store",
        # as listed in pandas
        choices=[
            "boxcar", "triang", "blackman", "hamming", "bartlett", "parzen",
            "bohman", "blackmanharris", "nuttall", "barthann"
        ],
        default="boxcar",
        help="Windowing algorithm"
    )
    parser.add_argument("--goodput", action="store_true",
        default=False,
        help="Drops retransmission from computation")
    return parser


# def _compute_tput(x, ):
#     """
#     Compares ack
#     Not an exact one, does not account for TCP sack for instance
#     """
#     # print("%s:\n%r" % (type(x), x))
#     # so now it gets a series

#     # print("max %f min %f average %d" % (x.max(), x.min(), averaging_window_int))
#     return (x.max() - x.min())/averaging_window_int

def _compute_tput(x, averaging_window_int):
    """
    Not an exact one, does not account for TCP sack for instance
    """
    # print("%s:\n%r" % (type(x), x))
    # so now it gets a series

    # print("max %f min %f average %d" % (x.max(), x.min(), averaging_window_int))
    return x.sum() / averaging_window_int
    # return (x.max() - x.min())/averaging_window_int




# the problem is that I still need to
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

    # TODO newdf Dataframe
    pdtime = time_col

    # print("Abstime")
    # print(pdtime)

    # import re
    # string1 = averaging_window
    # I should retreive the unit afterwards
    # averaging_window_int = int(re.search(r'\d+', string1).group())

    averaging_window_int = averaging_window
    averaging_window_str = f"{averaging_window}s"
    # TODO use it as index to use the rolling ?
    log.log(mp.TRACE, "MATT: computing tput over #seq=%d #time=%d", len(seq_col), len(time_col))

    # TODO test
    newdf = seq_col
    print("seq_col")
    print(seq_col)
    # newdf = pd.DataFrame(data={"seq": seq_col},) # index=pdtime)
    newdf = pd.DataFrame(seq_col)  # index=pdtime)
    # newdf["seq"] = seq_col
    # newdf.set_index(pdtime, drop=False, inplace=True)

    print("newdf")
    print(newdf.head())

    log.debug("Rolling over an interval of %s", averaging_window_str)

    try:

        # temp = newdf.rolling(
        #     # 3,
        #     # can be a number of an offset if index is datetime
        #     window=averaging_window_str,
        #     # parameters of interest too
        #     # min_periods=
        #     # on="tcpack",
        #     # closed="right",
        #     # center=True
        # )

        # # I think that's the culprit !!
        # # newdf["tput"] = temp.mean()

        # newdf["tput"] = temp.apply(
        #     partial(_compute_tput, averaging_window_int=averaging_window_int),
        #     raw=False,  # pass the data as a Serie rather than a numpy array
        #     # generates an unexpected keyword error ??!!!
        #     # convert_dtype=False,
        # )

        # seq_col
        # averaging_window_str
        # DatetimeIndexResampler [freq=<Second>, axis=0, closed=left, label=left, convention=start, base=0]
        # test
        df_summary = pd.DataFrame()
        # 's'
        # use mean instead
        df_summary["tput"] = newdf.tcplen.resample(averaging_window_str).sum()

        # .mean()
        print(df_summary)
        print(type(df_summary))

        return df_summary
    except ValueError as e:
        # print(e)
        # print(newdf.index)
        raise e


    # return newdf


def plot_tput(fig, *args, label=None):
    """
    Expects a dataframe with a certain format
    todo how to deal with legends
    Args:

    TODO generate legends ourselves
    """
    axes = fig.gca()

    log.debug("Plotting tput for %s", label)

    tput_df = compute_throughput(*args)
    # print("tput_df")
    # print(tput_df.dtypes)
    # print(tput_df)
    # astype("int64")
    tput_df.plot.line(
        ax=axes,
        legend=True,
        # TODO should depend from
        y="tput",
        label=label
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

        df = pcap
        window = kwargs.get("window")
        destinations = kwargs.get("pcap_destinations")

        print("Destinations", destinations)


        con = df.tcp.connection(pcapstream)
        df = con.fill_dest(df)

        debug_dataframe(df, "plotting TCP throughput")

        # la il faudrait resampler
        pd_abstime = pd.to_datetime(df[_sender("abstime")], unit="s", errors='raise', )
        df.set_index(pd_abstime, inplace=True)
        df.sort_index(inplace=True)

        # TODO at some point here, we lose the dest type :'(
        for dest, subdf in df.groupby("tcpdest"):
            if dest not in destinations:
                log.debug("Ignoring destination %s", dest)
                continue

            log.debug("Plotting destination %s", dest)

            label_fmt = "TCP stream {stream}"
            if len(destinations) >= 2:
                label_fmt = label_fmt + " towards {dest}"

            plot_tput(
                fig,
                subdf["tcplen"],
                # subdf["tcpack"],
                # subdf["abstime"],
                subdf.index,
                window,
                label=label_fmt.format(stream=pcapstream, dest=mp.ConnectionRoles(dest).to_string())
            )

        self.y_label = "Throughput (bytes/second)"

        # TODO fix connection towards a direction ?
        self.title_fmt = "TCP Throughput (Averaging window of {window}) for:\n{con:c<->s}".format(
            window=window,
            con=con
        )
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
        # return {
        #     'title_fmt': self.title_fmt,
        #     'title_args': {},
        #     'fig': fig
        # }


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
    def plot_dest(self, pcap, pcapstream, dest: mp.ConnectionRoles, **kwargs):
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
        final.add_argument('--skip-mptcp', action="store_true", default=False, help="")
        return final


    def plot(self, pcap, pcapstream, window, **kwargs):
        """
        TODO for now only plots subflows
        plots the mptcp aggregate or mptcpack instead ?
        """
        fig = plt.figure()

        df = pcap
        destinations = kwargs.get("pcap_destinations")

        con = df.mptcp.connection(pcapstream)
        df = con.fill_dest(df)

        if len(destinations) == 1:
            suffix = " towards MPTCP %s" % (destinations[0].to_string())
            self.title_fmt = self.title_fmt + suffix

        # origin
        pd_abstime = pd.to_datetime(df[_sender("abstime")], unit="s", errors='raise', )
        df.set_index(pd_abstime, inplace=True)
        df.sort_index(inplace=True)

        # then plots MPTCP level throughput
        ##################################################
        label_fmt = "MPTCP"
        if len(destinations) >= 2:
            label_fmt = label_fmt + " towards {mptcpdest}"

        for mptcpdest, subdf in df.groupby(_sender("mptcpdest")):
            # tcpdest, tcpstream, mptcpdest = idx
            mptcpdest = mp.ConnectionRoles(mptcpdest)
            if mptcpdest not in destinations:
                log.debug("Ignoring destination %s", mptcpdest)
                continue

            log.debug("Plotting mptcp destination %s", mptcpdest)

            plot_tput(
                fig,
                subdf["tcplen"],
                subdf["abstime"],
                window,
                label=label_fmt.format(mptcpdest=mptcpdest.to_string())
            )


        # plot subflows first...
        ##################################################
        fields = ["tcpstream", "tcpdest", "mptcpdest"]

        label_fmt = "Subflow {tcpstream}"
        if len(destinations) >= 2:
            label_fmt = label_fmt + " towards MPTCP {mptcpdest}"

        for idx, subdf in df.groupby(fields, sort=False):
            tcpstream, tcpdest, mptcpdest = idx
            mptcpdest = mp.ConnectionRoles(mptcpdest)
            if mptcpdest not in destinations:
                log.debug("Ignoring MPTCP destination %s", tcpdest)
                continue

            log.debug("Plotting tcp destination %s", tcpdest)


            # basically the same as for tcp
            plot_tput(
                fig,
                subdf["tcplen"],
                subdf.index,  # subdf["abstime"],
                window,
                label=label_fmt.format(tcpstream=tcpstream, mptcpdest=mptcpdest.to_string())
            )

        # return {
        #     'fig': fig
        # }
        return fig
