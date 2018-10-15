# -*- coding: utf-8 -*-
import mptcpanalyzer.plot as plot
import pandas as pd
import argparse
import matplotlib.pyplot as plt
from mptcpanalyzer.statistics import mptcp_compute_throughput
import collections
from typing import List
import logging

log = logging.getLogger(__name__)


def compute_goodput(df):
    """
    wiereshakr example can be found in:
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


    # df.rolling(3, on="bytes", win_type=).apply(np.mean).dropna()
    return df

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
        parser = super().default_parser(
            *args, parents=[parent],
            direction=True,
            skip_subflows=True,
            **kwargs
        )
        return parser

    def preprocess(self, pcap1, pcap2, pcap1stream, pcap2stream, **kwargs):
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
            df = woo.load_merged_streams_into_pandas(
                pcap1,
                pcap2,
                pcap1stream,
                pcap2stream,
                # kwargs.get(""),
                # kwargs.get("stream2"),
                True,
                # TODO how does it get the config
                self.tshark_config,
            )

            # then we need to process throughput/goodput
            # Later move it to utils so that it can be used in
            # summary_extended (to plot average/min/max)
            for idx, subdf in df.groubpy(_sender(["tcpstream", "tcpdest"])):

                compute_df(subdf)
            return df

        except Exception as e:
            logging.exception()
            raise e
            # log.debug("Could not load cached results %s" % cachename)


    def plot(self, dat, destinations, **kwargs):
        """
        getcallargs
        """

        fig = plt.figure()
        success, ret = mptcp_compute_throughput(dat, mptcpstream, destination)
        if success is not True:
            print("Failure: %s", ret)
            return


        # TODO use df.rolling
        rolling

        data = map(lambda x: x['bytes'], ret['subflow_stats'])
        s = pd.DataFrame(data=pd.Series(data))
        print (s)

        # gca = get current axes (Axes), create one if necessary
        axes = fig.gca()
        s.T.plot.bar(stacked=True, by=None, ax=axes);
        # pd.Series
        # .hist(
        # for idx, (streamid, ds) in enumerate(tcpstreams):
        #     ds[field].plot.line(
        #         ax=axes,
        #         # use_index=False,
        #         legend=False,
        #         grid=True,
        #     )

        axes.set_xlabel("Time (s)")

        # TODO plot on one y the throughput; on the other the goodput
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
