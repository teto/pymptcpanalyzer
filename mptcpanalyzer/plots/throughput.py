# -*- coding: utf-8 -*-
import mptcpanalyzer.plot as plot
import pandas as pd
import argparse
import matplotlib.pyplot as plt
from mptcpanalyzer import _receiver, _sender, PreprocessingActions
from mptcpanalyzer.statistics import mptcp_compute_throughput
from mptcpanalyzer.data import load_merged_streams_into_pandas
import collections
from typing import List
import logging

log = logging.getLogger(__name__)

# field="ack"
def compute_goodput(df, averaging_window):
    """
    wireshark example can be found in:
    ui/qt/tcp_stream_dialog.cpp: void TCPStreamDialog::fillThroughput()

    // Throughput Graph - rate of sent bytes
    // Goodput Graph - rate of ACKed bytes

    todo should make it work with dack/ack
    problem is we don't support sack :'(

    Adds following columns to the dataframe:
    - tput
    - gput 
    - dt_abstime: abstime but in datetime format so that one can apply "rolling" features
    """
    # df.rolling(on="bytes")
    # we can use mptcp.ack
    # we can use tcp.ack that are relative
    # rolling window can use offset

    # assert (field == "tcpack" or field "dack")

    df[_sender("dt_abstime")] = pd.to_datetime(df[_sender("abstime")], unit="s")

    print(df["dt_abstime"])
    import re
    string1 = averaging_window
    # TODO I should retreive the unit afterwards
    averaging_window_int = int(re.search(r'\d+', string1).group())

    # TODO use it as index to use the rolling ?
    # win_type=
    # rolling 
    def _compute_tput(x, ):
        """
        Not an exact one, does not account for TCP sack for instance
        """
        print("compute_tput called !!")
        # print("%r" % x )
        # so now it gets a series
        return (x.max() - x.min())/averaging_window_int

    # TODO test 
    newdf= df.set_index("dt_abstime", drop=False)

    print(newdf[["abstime", "tcpack"]])
    newdf["tput"] = newdf["tcpack"].rolling(
        # 3,
        averaging_window,
        # on="tcpack",
        # closed="right",
        # center=True
    # ).mean()
    ).apply(_compute_tput, raw=False, )  # args=(), kwargs={} 

    print("AFTER rolling ")
    print(newdf[["abstime", "tcpack", "tput"]].head(5))
    return newdf



class SubflowThroughput(plot.Matplotlib):
    """
    Plot subflow throughput
    Mptcp throughput equals the sum of subflow contributions
    """

    def __init__(self, *args, **kwargs):
        pcaps = {
            "pcap1": plot.PreprocessingActions.DoNothing,
            "pcap2": plot.PreprocessingActions.DoNothing,
        }
        super().__init__(
            *args,
            input_pcaps=pcaps,
            **kwargs
        )

    def default_parser(self, *args, **kwargs):

        parent = argparse.ArgumentParser(
            description="Helps plotting Data sequence numbers"
        )
        parent.add_argument("protocol", choices=["tcp", "mptcp"], action="store",
            help="what kind to plot")
        parser = super().default_parser(
            *args, parents=[parent],
            direction=True,
            skip_subflows=True,
            **kwargs
        )
        parser.add_argument("window", metavar="AVG_WINDOW", action="store", type=str, 
                default=3,
            help="Averaging window , for instance '1s' ")
        return parser

    def preprocess(self, pcap1, pcap2, pcap1stream, pcap2stream, protocol, **kwargs):
        """
        This is trickier than in other modules: this plot generates intermediary results
        to compute OWDs.
        These results can be cached in which  case it's not necessary
        to load the original pcaps.

        First we get the cachename associated with the two pcaps. If it's cached we load
        directly this cache else we proceed as usual

        """
        log.debug("Preprocessing")
        # if we can't load that file from cache
        try:

            #TODO pass clockoffsets
            # Need to add the stream ids too !
            merged_df = load_merged_streams_into_pandas(
                pcap1,
                pcap2,
                pcap1stream,
                pcap2stream,
                # kwargs.get(""),
                # kwargs.get("stream2"),
                protocol == "mptcp",
                # TODO how does it get the config
                self.tshark_config,
            )

            # first test on TCP


            # then we need to process throughput/goodput
            # Later move it to utils so that it can be used in
            # summary_extended (to plot average/min/max)
            # for idx, subdf in df.groubpy(_sender(["tcpstream", "tcpdest"])):
            #     print("computing tput")

            #     compute_df(subdf)
            return merged_df

        except Exception as e:
            logging.exception("Error while plotting throughput")
            raise e
            # log.debug("Could not load cached results %s" % cachename)


    def plot(self, dat, destinations, **kwargs):
        """
        getcallargs
        """

        fig = plt.figure()
        axes = fig.gca()

        # success, ret = mptcp_compute_throughput(dat, mptcpstream, destination)
        # if success is not True:
        #     print("Failure: %s", ret)
        #     return


        # data = map(lambda x: x['bytes'], ret['subflow_stats'])
        # s = pd.DataFrame(data=pd.Series(data))
        # print (s)

        # gca = get current axes (Axes), create one if necessary
        axes = fig.gca()

        fields = "tcpdest", "tcpstream"
        for idx, subdf in dat.groupby(_sender(fields), sort=False):
            stream, tcpdest = idx

            tput_df = compute_goodput(subdf, kwargs.get("window"))
            tput_df.plot.line(
                ax=axes,
                legend=True,
                # TODO should depend from 
                x=_sender("dt_abstime"),
                y="tput",
                # y="gput",
                label="Xput towards %s" % tcpdest, # seems to be a bug
            )


        # TODO plot on one y the throughput; on the other the goodput
        axes.set_xlabel("Time (s)")
        axes.set_ylabel("contribution")
        fig.suptitle("Subflow throughput/goodput")

        # handles, labels = axes.get_legend_handles_labels()

        # # Generate "subflow X" labels
        # # location: 3 => bottom left, 4 => bottom right
        # axes.legend(
        #     handles,
        #     ["%s for Subflow %d" % (field, x) for x, _ in enumerate(labels)],
        #     loc=4
        # )

        return fig
