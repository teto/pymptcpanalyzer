#!/usr/bin/env python
# -*- coding: utf-8 -*-


import mptcpanalyzer as mp
# from mptcpanalyzer.data import load_into_pandas
import mptcpanalyzer.plot as plot
import mptcpanalyzer.data as woo
# import mptcpanalyzer
from mptcpanalyzer.connection import MpTcpConnection, TcpConnection
import pandas as pd
import logging
import matplotlib.pyplot as plt
import os
import argparse
# import math
import collections
from mptcpanalyzer.cache import CacheId

from typing import Iterable, List #, Any, Tuple, Dict, Callable

# global log and specific log
log = logging.getLogger(__name__)
slog = logging.getLogger("owd")


# This is a complex plot hence we added some
# debug variables
mock_cachename = "backup.csv"
# limit = 20


class TcpOneWayDelay(plot.Matplotlib):
    """
    The purpose of this plot is to display the "one-way delay" (OWD) (also called
    one-way latency (OWL)) between the client
    and the server.
    To do this, you need to capture a communication at both ends, client and server.

    Wireshark assigns an id (mptcp.stream) to each mptcp communications, ideally this plugin
    could try to match both ids but for now you need

    .. note:: both hosts should have their clock synchronized. If this can be hard
    with real hosts, perfect synchronization is available in network simulators
    such as ns3.


    This format allows

    .. _owd-cache-format:
        It creates an intermediate cache file of the form
        host1pktId, host2pktId, score, owd, ipsrc_h1, ipsrc_h2, etc...


    .. warning:: This plugin is experimental.
    """

    def __init__(self, *args, **kwargs):

        # peu importe l'ordre plutot
        expected_pcaps = [
            ("host1_pcap", plot.PreprocessingActions.Preload),
            ("host2_pcap", plot.PreprocessingActions.Preload),
        ]
        super().__init__(
               *args,
               input_pcaps=expected_pcaps,
               **kwargs
        )

        self.tshark_config.filter = "tcp";
        # self.suffixes = ("_snd", "_rcv")
        # self.suffixes = ("", "_rcv")
        # self.columns = [
        #     "owd",
        #     "abstime" + self.suffixes[0],
        #     "abstime" + self.suffixes[1],
        #     "packetid" + self.suffixes[0],
        #     "packetid" + self.suffixes[1],
        #     "ipsrc" + self.suffixes[0],
        #     "ipsrc" + self.suffixes[1],
        #     "ipdst" + self.suffixes[0],
        #     "ipdst" + self.suffixes[1],
        #     "sport" + self.suffixes[0],
        #     "sport" + self.suffixes[1],
        #     "dport" + self.suffixes[0],
        #     "dport" + self.suffixes[1],
        #     "tcpseq"
        # ]


    def default_parser(self, *args, **kwargs):
        parser = argparse.ArgumentParser(
            description="Helps plotting One Way Delays between tcp connections"
        )
        # parser.add_argument("host1", action="store", help="pcap captured on first host")
        # parser.add_argument("host2", action="store", help="pcap captured on second host")
        parser = super().default_parser(
            *args, parent_parsers=[parser], mptcpstream=False, **kwargs
        )

        # parser.add_argument("--offset", action="store",
        #         type=float,
        #         help="A possible offset added to the time of"
        # )

        return parser


#    def get_cachename(self, pcap1, pcap2):
#        """
#        fake cachename via concatenating
#        Ideally the order of parameters should not matter
#        """
#        # TODO HACK mock
#        return mock_cachename
#        return os.path.join(pcap1, os.path.sep, pcap2)

    def preprocess(self, main, mptcpstream=None,
            # host1_pcap, host2_pcap,
            **kwargs):
        """
        This is trickier than in other modules: this plot generates intermediary results
        to compute OWDs.
        These results can be cached in which  case it's not necessary
        to load the original pcaps.

        First we get the cachename associated with the two pcaps. If it's cached we load
        directly this cache else we proceed as usual

        TODO generate cachename from dependencies basenames :
        """
        # h1, h2 = super().preprocess()
        cacheid = CacheId("owd", [
            # host1_pcap,
            kwargs.get("host1_pcap"),
            kwargs.get("host2_pcap")
            ], ".csv")

        print(" main = %r", main)
        # if we can't load that file from cache
        try:
            cache = mp.get_cache()

            valid, cachename = cache.get(cacheid)
            log.info("Cache validity=%s and cachename=%s" % (valid, cachename))
            # print(**kwargs)
            print(kwargs)

            if not valid:
                # generate h1/h2 cache
                dataframes = super().preprocess(main, **kwargs)
                # tcpstream = mptcpstream # we kept mptcpstream as a convenience
                # TODO 
                print("FIX tcpstreamid AFTER DEBUG")
                tcpstream = 0 # we kept mptcpstream as a convenience

                # we want to save results as a single file (easier to loader etc...)
                # so we concat ?
                # self.generate_owd_df(dataframes, cachename, **kwargs)
                # print("len=%d" % len(dataframes))
                assert len(dataframes) == 2, "Preprocess host1 and host2 pcaps"
                h1_df, h2_df = dataframes

                total = woo.merge_tcp_dataframes(h1_df, h2_df, tcpstream)
                firstcols = ['packetid_h1', 'packetid_h2', 'dest', 'owd']
                total = total.reindex(columns=firstcols + list(filter(lambda x: x not in firstcols, total.columns.tolist())))
                print("Saving into %s", cachename)
                total.to_csv(
                    cachename, # output
                    # columns=columns,
                    index=False,
                    header=True,
                    # sep=main.config["DEFAULT"]["delimiter"],
                )
                return total


            else:
                log.info("Loaded from cache")
                # pd.read_csv()
                with open(cachename) as fd:
                    # first line is metadata
                    # TODO: creer classe metadata read/write ?
                    # metadata = fd.readline()

                    data = pd.read_csv(
                        fd,
                        # skip_blank_lines=True,
                        # hum not needed with comment='#'
                        comment='#',
                        # we don't need 'header' when metadata is with comment
                        # header=mp.METADATA_ROWS, # read column names from row 2 (before, it's metadata)
                        # skiprows
                        sep=self.config.delimiter,
                        # dtype=dtypes,
                        # converters={
                        #     "tcp.flags": lambda x: int(x, 16),
                        #     # reinjections, converts to list of integers
                        #     "mptcp.duplicated_dsn": lambda x: list(map(int, x.split(','))) if x else np.nan,
                        #     # "mptcp.related_mapping": lambda x: x.split(','),
                        # },
                        # memory_map=True, # could speed up processing
                    )
                    # TODO:
                    # No columns to parse from file
                    # data.rename(inplace=True, columns=config.get_fields("fullname", "name"))
                    log.debug("Column names: %s", data.columns)

                return data

        except Exception as e:
            print("exception happened %s" % e )
            raise e
            # log.debug("Could not load cached results %s" % cachename)

        # log.info("Regenerating from cache")
        # columns = data.generate_columns([], [], data.suffixes)
        # return None

    #def do_plot_owd(self, args):
    def plot(self, df_results, mptcpstream=None, **kwargs):
        """
        Ideally it should be mapped automatically
        For now plots only one direction but there could be a wrapper to plot forward owd, then backward OWDs
        Disclaimer: Keep in mind this assumes a perfect synchronization between nodes, i.e.,
        it relies on the pcap absolute time field.
        While this is true in discrete time simulators such as ns3

        See
        Todo:
            it should be possible to cache intermediary results (computed owds)

        """
        # assert mptcpstream is not None, "parser should provide automatically this"

        # prepare a plot
        fig = plt.figure()
        axes = fig.gca()

        res = df_results
        print("columns", res.columns)

        # print(res[["packetid", "mapped_index",
        #     "sendkey" + self.suffixes[0], "sendkey" + self.suffixes[1],]])

        # need to compute the owd depending on the direction right
        # res['owd'] = res['abstime_y'] - res['abstime_x']
        # TODO groupby ('tcpstream', 'dest')

        # group by title/direction
        # todo utiliser groupby

        print(res["tcpdest"].head())
        cols = ["tcpstream_h1", "tcpstream_h2", "tcpdest"]
        # cols = ["tcpstream_h1", "tcpstream_h2", ]
        # print(res)
        # print(res.columns)
        # print(res.dtypes)

        grouped_by = res.groupby(cols, sort=False)
        print(grouped_by.head())
        print(len(grouped_by)) # len of 2 which is good, but why

        for idx, df in grouped_by:
            print("ID=" , idx)
            print("df = ", df)

            # df = debug_convert(df)
            pplot = grouped_by.plot.line(
                # gca = get current axes (Axes), create one if necessary
                ax=axes,
                legend=False,
                x="abstime_h1",
                y="owd",
                label="toto", # seems to be a bug
                # style="-o",
                # grid=True,
                # xticks=tcpstreams["reltime"],
                # rotation for ticks
                # rot=45,
                # lw=3
            )

        # set min(abstime_h1, abstime_2) as index
        # passe un label a chaque plot alors ?
        # pplot = grouped_by.plot.line(
        #     # gca = get current axes (Axes), create one if necessary
            # ax=axes,
            # legend=False,
            # x="abstime_h1",
            # y="owd",
            # # style="-o",
            # # grid=True,
            # # xticks=tcpstreams["reltime"],
            # # rotation for ticks
            # # rot=45,
            # # lw=3
        # )
        axes.legend(['toto', 'ta'])
        # handles, labels = axes.get_legend_handles_labels()
        # print("labels=", labels)

        # TODO add units
        axes.set_xlabel("Time (s)")
        axes.set_ylabel("One Way Delay (s)")
        return fig



# class MpTcpOneWayDelay(TcpOneWayDelay):
#     """
#     Same as TcpOneWayDelay but for several

#     Todo:
#         support skipping streams
#     """

#     def preprocess(self, main, mptcpstream=None, **kwargs):
#         """
#         This is trickier than in other modules: this plot generates intermediary results
#         to compute OWDs. There results can be cached in which  case it's not necessary
#         to load the original pcaps

#         First we get the cachename associated with the two pcaps. If it's cached we load
#         directly this cache else we proceed as usual
#         """
#         cachename = self.get_cachename(kwargs.get("client_pcap"), kwargs.get("server_pcap"))
#         # if we can't load that file from cache
#         try:
#             df = main.load_into_pandas(cachename)
#             input("Loaded from cache")
#             return df
#         except Exception:
#             log.debug("Could not load cached results %s" % cachename)
#         # if main.cache.is_cache_valid():
#         #     pd.read_csv

#         dataframes = super().preprocess(main, mptcpstream=mptcpstream, **kwargs)

#         # we want to save results as a single file (easier to loader etc...)
#         # so we concat ?
#         # self.generate_owd_df(dataframes, cachename, **kwargs)
#         print("len(df)=", len(dataframes))
#         df1, df2 = dataframes
#         main_connection = data.MpTcpConnection.build_from_dataframe(df1, mptcpstream)

#         # du coup on a une liste
#         mappings = data.mptcp_match_connection(df2, main_connection)

#         print("Found mappings %s" % mappings)
#         # returned a dict
#         # if mptcpstream not in mappings:
#         #     print("Could not find ptcpstream %d in the first pcap" % mptcpstream)
#         #     return
#         # print("Number of %d" % len(mappings[mptcpstream]))
#         # print("#mappings=" len(mappings):
#         if len(mappings) <= 0:
#             print("Could not find a match in the second pcap for mptcpstream %d" % mptcpstream)
#             return

#         # limit number of packets while testing
#         # HACK to process faster
#         df1 = df1.head(limit)
#         df2 = df2.head(limit)

#         print("len(df1)=", len(df1), " len(rawdf2)=", len(rawdf2))
#         # mappings
#         mapped_connection, score = mappings[0]

#         # some subflows may have been blocked by routing/firewall
#         common_subflows = []
#         for sf in main_connection.subflows:
#             # if sf2 in
#             for sf2 in mapped_connection.subflows:
#                 if sf == sf2:
#                     common_subflows.append((sf, sf2))
#                     break

#             # try:
#             #     idx = mapped_connection.subflows.index(sf)
#             #     sf2 = mapped_connection.subflows[idx]
#             #     common_subflows.append((sf, sf2))

#             # except ValueError:
#             #     continue

#         # common_subflows = set(mapped_connection.subflows, main_connection.subflows)
#         print("common sf=%s", common_subflows)
#         assert len(common_subflows) > 0, "Should be at least one common sf"
#         # print(mappings)
#         print("Found mappings %s" % mappings)
#         return
