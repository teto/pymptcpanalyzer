# -*- coding: utf-8 -*-
import mptcpanalyzer.plot as plot
import pandas as pd
import argparse
import matplotlib.pyplot as plt
from mptcpanalyzer import _receiver, _sender, PreprocessingActions
from mptcpanalyzer.statistics import mptcp_compute_throughput
from mptcpanalyzer.data import load_merged_streams_into_pandas
from mptcpanalyzer.parser import gen_pcap_parser, MpTcpAnalyzerParser
from mptcpanalyzer.pdutils import debug_dataframe
import collections
from typing import List
import logging

log = logging.getLogger(__name__)


def compute_goodput(df, averaging_window):
    raise NotImplemented("Please implement me")

def compute_throughput(df, averaging_window) -> pd.DataFrame:
    """
    Args:
        averaging_window:


    Converts time series into pandas format so that we can use the rolling window 
    algorithm on it

    Adds following columns to the dataframe:
    - tput
    - gput 
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

    df[_sender("dt_abstime")] = pd.to_datetime(df[_sender("abstime")], unit="s")

    print(df["dt_abstime"])
    # import re

    # TODO 
    # string1 = averaging_window

    # # TODO I should retreive the unit afterwards
    # averaging_window_int = int(re.search(r'\d+', string1).group())

    averaging_window_int = averaging_window
    averaging_window_str = "%ss" % averaging_window
    # TODO use it as index to use the rolling ?
    def _compute_tput(x, ):
        """
        Not an exact one, does not account for TCP sack for instance
        """
        print("compute_tput called !!")
        print("%s:\n%r" % (type(x), x))
        # so now it gets a series

        print("max %f min %f average %d" % (x.max(), x.min(), averaging_window_int))
        return (x.max() - x.min())/averaging_window_int

    # TODO test
    newdf = df.set_index("dt_abstime", drop=False)

    print(newdf[["dt_abstime", "abstime", "tcpack"]])

    log.debug("Rolling over an interval of %s" % averaging_window_str)
    temp = newdf["tcpack"].astype("float64").rolling(

        # 3,
        # can be a number of an offset for datetime based
        window=averaging_window_str,
        # interesting parameter too
        # min_periods=
        # on="tcpack",
        # closed="right",
        # center=True
    )

    # raw=False,
    newdf["tput"] = temp.apply(
        _compute_tput,
        # pass the data as a Serie rather than a numpy array
        raw=False,
        #
        # convert_dtype=False,
    )

    print("AFTER rolling ")
    print(newdf[["abstime", "tcpack", "tput"]].head(5))
    return newdf



# TODO create 
class SubflowThroughput(plot.Matplotlib):
    """
    Plot subflow throughput
    Mptcp throughput equals the sum of subflow contributions
    """

    def default_parser(self, *args, **kwargs):

        parser = MpTcpAnalyzerParser(
            description="Helps plotting Data sequence numbers"
        )
        parser.epilog = """
            plot throughput tcp examples/client_2_redundant.pcapng 0 examples/server_2_redundant.pcapng 0 3
        """
        # return parser
        res = super().default_parser(
            *args, parents=[parser],
            **kwargs
        )

        pcaps = {
            "pcap": PreprocessingActions.Preload | PreprocessingActions.FilterStream
        }
        final = gen_pcap_parser(pcaps, parents=[res], direction=True)

        # passed window 3 is not compatible with a datetimelike index
        final.add_argument("window", metavar="AVG_WINDOW", action="store",
            type=int, default=3,
            help="Averaging window , for instance '1s' "
        )
        return final


    # TODO add window / destinations ?
    # dat, destinations,
    def plot(self, pcap, pcapstream, **kwargs):
        """
        getcallargs
        """

        fig = plt.figure()
        axes = fig.gca()

        df = pcap
        window = kwargs.get("window")
        destinations = kwargs.get("pcap_destinations")
        # success, ret = mptcp_compute_throughput(df, mptcpstream, destination)
        # if success is not True:
        #     print("Failure: %s", ret)
        #     return

        # data = map(lambda x: x['bytes'], ret['subflow_stats'])
        # s = pd.DataFrame(data=pd.Series(data))
        # print (s)


        title = "TCP throughput/goodput"

        # group by tcpstream
        # fields = ["tcpdest", "tcpstream", ]
        # if mptcp_plot:
        #     fields.append("mptcpdest")
        #     title = "MPTCP throughput/goodput"

        print("Destinations", destinations)


        con = df.tcp.connection(pcapstream)
        df = con.fill_dest(df)

        # groups = df.groupby(_sender("tcpdest"), sort=False)

        debug_dataframe(df, "plotting throughput" )
        # print("groups: %r" % groups)
        # for idx, subdf in groups:
        for dest, subdf in df.groupby(_sender("tcpdest")):
            if dest not in destinations:
                log.debug("Ignoring destination %s" % dest)
                continue

            log.debug("Plotting destination %s" % dest)

            # filler in case
            # stream, tcpdest, mptcpdest, _catchall = (*idx, "filler1", "filler2") # type: ignore

            # log.debug("filtereddest == %s" % filtereddest)

            tput_df = compute_throughput(subdf, window)
            tput_df.plot.line(
                ax=axes,
                legend=True,
                # TODO should depend from 
                x=_sender("dt_abstime"),
                y="tput",
                # y="gput",
                label="Xput towards %s" % dest, # seems to be a bug
            )


        # TODO plot on one y the throughput; on the other the goodput
        axes.set_xlabel("Time (s)")
        axes.set_ylabel("contribution")
        fig.suptitle(title)

        # handles, labels = axes.get_legend_handles_labels()

        # # Generate "subflow X" labels
        # # location: 3 => bottom left, 4 => bottom right
        # axes.legend(
        #     handles,
        #     ["%s for Subflow %d" % (field, x) for x, _ in enumerate(labels)],
        #     loc=4
        # )

        return fig


class MptcpThroughput(plot.Matplotlib):
    """
    """
    pass

