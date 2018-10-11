import mptcpanalyzer as mp
from mptcpanalyzer import _receiver, _sender
import mptcpanalyzer.plot as plot
import mptcpanalyzer.data as woo
from mptcpanalyzer.connection import MpTcpConnection, TcpConnection
import pandas as pd
import logging
import matplotlib.pyplot as plt
import matplotlib as mpl
import os
import argparse
import collections
from mptcpanalyzer.cache import CacheId
from cmd2 import argparse_completer
from typing import Iterable, List #, Any, Tuple, Dict, Callable
from itertools import cycle

# global log and specific log
log = logging.getLogger(__name__)


TCP_DEBUG_FIELDS = ['hash', 'ipsrc', 'ipdst', 'tcpstream', 'packetid', "reltime", "abstime", "tcpdest"]

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

        # expected_pcaps = [
        #     ("host1_pcap", plot.PreprocessingActions.Preload),
        #     ("host2_pcap", plot.PreprocessingActions.Preload),
        # ]
        super().__init__(
            *args,
            input_pcaps=[],
            **kwargs
        )

        self.tshark_config.filter = "tcp";
        # print("owd tcp", self.tshark_config.fields)
        # TODO a purer version would be best
        # self.tshark_config.fields = []
        # self.tshark_config.add_basic_fields();


    def default_parser(self, *args, **kwargs):
        parser = super().default_parser()
        subparsers = parser.add_subparsers(dest="protocol",
            title="Subparsers", help='Choose protocol help',)

        subparsers.required = True  # type: ignore
        
        tcpparser = mp.gen_bicap_parser("tcp", True)
        mptcpparser = mp.gen_bicap_parser("mptcp", True)

        subparsers.add_parser("tcp", parents=[tcpparser], add_help=False)
        subparsers.add_parser("mptcp", parents=[mptcpparser], add_help=False)

            
        parser.description = "Helps plotting One Way Delays between tcp connections"

        return parser


    def preprocess(self, protocol, pcap1, pcap2, **kwargs):
        """
        This is trickier than in other modules: this plot generates intermediary results
        to compute OWDs.
        These results can be cached in which  case it's not necessary
        to load the original pcaps.

        First we get the cachename associated with the two pcaps. If it's cached we load
        directly this cache else we proceed as usual

        """
        logging.debug("Preprocess for protocol %s" % protocol)
        # if we can't load that file from cache
        try:

            #TODO pass clockoffsets
            # Need to add the stream ids too !
            df = woo.load_merged_streams_into_pandas(
                pcap1,
                pcap2,
                kwargs.get(protocol + "stream"),
                kwargs.get(protocol + "stream2"),
                protocol == "mptcp",
                # TODO how does it get the config
                self.tshark_config,
            )

            return df

        except Exception as e:
            logging.exception()
            raise e
            # log.debug("Could not load cached results %s" % cachename)

        # here we recompute the OWDs

    def plot(self, res, **kwargs):
        """
        Ideally it should be mapped automatically
        For now plots only one direction but there could be a wrapper to plot forward owd, then backward OWDs
        Disclaimer: Keep in mind this assumes a perfect synchronization between nodes, i.e.,
        it relies on the pcap absolute time field.
        While this is true in discrete time simulators such as ns3

        """
        fig = plt.figure()
        axes = fig.gca()

        # TODO here we should rewrite
        debug_fields = _sender(TCP_DEBUG_FIELDS) + _receiver(TCP_DEBUG_FIELDS) + [ "owd" ]

        # print(res.loc[res._merge == "both", 
        print("columns", res.columns)
        print("info", res.info())
        print(res.loc[res._merge == "both", debug_fields ])

        # print(res[["packetid", "mapped_index",
        #     "sendkey" + self.suffixes[0], "sendkey" + self.suffixes[1],]])

        # need to compute the owd depending on the direction right
        # res['owd'] = res['abstime_y'] - res['abstime_x']
        # TODO groupby ('tcpstream', 'dest')

        # group by title/direction
        # todo utiliser groupby
        # print("Plotting is not ready yet ")
        # exit(1)

        # print(res["tcpdest"].head())
        # cols = "tcpdest"
        # cols = ["tcpstream_h1", "tcpstream_h2", ]
        # print(res)
        # print(res.columns)
        # print(res.dtypes)
# df.reset_index(drop=True)
        # grouped_by = res.groupby(by=cols, sort=False)
        # print(res.head())
        # print(res[['tcpdest']])
        # print(res[:,'tcpdest'])
        # grouped_by = res.groupby(by=cols, )
        # print(grouped_by.head())
        # print(len(grouped_by)) # len of 2 which is good, but why

        cycler = mpl.cycler(marker=['s', 'o', 'x'], color=['r', 'g', 'b'])
        markers = cycle(cycler)


        # TODO la faut que ca marche pour les 2 cas mptcp/tcp

        # TODO cycle through styles
        for tcpdest, df in res.groupby(_sender("tcpdest")):
            marker = next(markers)

            # df = debug_convert(df)
            pplot = df.plot.line(
                # gca = get current axes (Axes), create one if necessary
                ax=axes,
                legend=True,
                # TODO should depend from 
                x=_sender("abstime"),
                y="owd",
                label="TCP stream %s" % tcpdest, # seems to be a bug
                style=marker,
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

        # why are these so wrong !
        # axes.legend(['toto', 'ta'])

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
