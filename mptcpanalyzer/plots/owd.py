#!/usr/bin/env python
# -*- coding: utf-8 -*-


import mptcpanalyzer as mp
import mptcpanalyzer.plot as plot
import mptcpanalyzer.data as data
from mptcpanalyzer.connection import MpTcpConnection, TcpConnection
import pandas as pd
import logging
import matplotlib.pyplot as plt
import os
import argparse
import math


log = logging.getLogger(__name__)


# This is a complex plot hence we added some
# debug variables
mock_cachename = "backup.csv"
limit = 10



class TcpOneWayDelay(plot.Matplotlib):
    """
    The purpose of this plot is to display the one-way delay between the client 
    and the server.
    To do this, you need to capture a communication at both ends, client and server.

    Wireshark assigns an id (mptcp.stream) to each mptcp communications, ideally this plugin
    could try to match both ids but for now you need

    .. note:: both hosts should have their clock synchronized. If this can be hard
    with real hosts, perfect synchronization is available in network simulators
    such as ns3.

    .. warning:: This plugin is experimental.
    """

    def __init__(self, *args, **kwargs):

        expected_pcaps = {
            "client_pcap": plot.PreprocessingActions.Preload,
            "server_pcap": plot.PreprocessingActions.Preload,
        }
        super().__init__(preload_pcaps=expected_pcaps, *args, **kwargs)
        # self.suffixes = ("_snd", "_rcv")
        self.suffixes = ("", "_rcv")
        self.columns = [
            "owd", 
            "abstime" + self.suffixes[0], 
            "abstime" + self.suffixes[1], 
            "packetid" + self.suffixes[0], 
            "packetid" + self.suffixes[1], 
            "tcpseq"
        ] 


    def default_parser(self, *args, **kwargs):
        parser = argparse.ArgumentParser(
            description="Helps plotting One Way Delays between tcp connections"
        )
        # parser.add_argument("host1", action="store", help="pcap captured on first host")
        # parser.add_argument("host2", action="store", help="pcap captured on second host")
        parser = super().default_parser(*args, parent_parsers=[parser], mptcpstream=True, **kwargs)

        # parser.add_argument("host2", action="store",
        #         help="Either a pcap or a csv file (in good format)."
        # )

        return parser


    def get_cachename(self, pcap1, pcap2):
        """fake cachename via concatenating 
        """
        # TODO HACK mock
        return mock_cachename
        return os.path.join(pcap1, os.path.sep, pcap2)

    def preprocess(self, main, mptcpstream=None, **kwargs):
        """
        This is trickier than in other modules: this plot generates intermediary results
        to compute OWDs. There results can be cached in which  case it's not necessary
        to load the original pcaps

        First we get the cachename associated with the two pcaps. If it's cached we load 
        directly this cache else we proceed as usual
        """
        cachename = self.get_cachename(kwargs.get("host1"), kwargs.get("host2"))
        # if we can't load that file from cache
        try:
            df = main.load_into_pandas(cachename)
            return df
        except Exception:
            log.debug("Could not load cached results %s" % cachename)

        dataframes = super().preprocess(main, mptcpstream=mptcpstream, **kwargs)

        # we want to save results as a single file (easier to loader etc...)
        # so we concat ?
        # self.generate_owd_df(dataframes, cachename, **kwargs)
        client_df, server_df = dataframes
        main_connection = TcpConnection.build_from_dataframe(client_df, mptcpstream)

        # # du coup on a une liste
        mappings = data.map_tcp_stream(server_df, main_connection)

        print("Found mappings %s" % mappings)
        if len(mappings) <= 0:
            print("Could not find a match in the second pcap for mptcpstream %d" % mptcpstream)
            return 


        # limit number of packets while testing 
        # HACK to process faster
        client_df = client_df.head(limit)
        server_df = server_df.head(limit)

        print("len(df1)=", len(client_df), " len(rawdf2)=", len(server_df))
        mapped_connection, score = mappings[0]
        print("Found mappings %s" % mappings)
        for con, score in mappings:
            print("Con: %s" % (con))

        print("Mapped connection %s to %s" % (mapped_connection, main_connection))

        #  mapped_connection should be of type TcpConnection

        # TODO we clean accordingly
        # TODO for both directions
        # total_results
        total = None # pd.DataFrame()
        for dest in mp.Destination:
            q = main_connection.generate_direction_query(dest)
            local_sender_df = client_df.query(q)
            q = mapped_connection.generate_direction_query(dest)
            local_receiver_df = server_df.query(q)

            if dest == mp.Destination.Client:
                local_sender_df, local_receiver_df = local_receiver_df, local_sender_df
            res = self.generate_owd_df(local_sender_df, local_receiver_df)
            res['dest'] = dest
            total = pd.concat([res, total])

            filename = "merge_%d_%s.csv" % (mptcpstream, dest)
            res.to_csv(
                filename, # output
                columns=self.columns, 
                index=True,
                header=True,
                # sep=main.config["DEFAULT"]["delimiter"],
            )

        # filename = "merge_%d_%d.csv" % (tcpstreamid_host0, tcpstreamid_host1)
        res.to_csv(
            cachename, # output
            columns=self.columns, 
            index=True,
            header=True,
            # sep=main.config["DEFAULT"]["delimiter"],
        )
        return total



    # TODO faire une fonction pour TCP simple
    def generate_owd_df(self, sender_df, receiver_df, **kwargs):
        """
        Generate owd in one sense
        sender_df and receiver_df must be perfectly cleaned beforehand
        Attr:

        Returns 
        """

        log.info("Generating intermediary results")

        # sender_df.set_index('packetid', inplace=True)
        # rawdf2.set_index('packetid', inplace=True)

        # df1 = self.filter_dataframe(rawdf1, mptcpstream=mptcpstream, **kwargs)
        # now we take only the subset matching the conversation

        # limit number of packets while testing 
        # HACK to process faster
        df1 = sender_df.head(limit)
        rawdf2 = receiver_df.head(limit)
        print("len(df1)=", len(df1), " len(rawdf2)=", len(rawdf2))
        print("df1=\n", (df1))
        #" len(rawdf2)=", len(rawdf2))


        # this will return rawdf1 with an aditionnal "mapped_index" column that
        # correspond to 
        mapped_df = data.map_tcp_packets(df1, rawdf2)

        # TODO print statistics about how many packets have been mapped
        # print(" len(mapped_df)")
        # should print packetids

        print("== DEBUG START ===")
        print("Mapped index:")
        print(mapped_df["mapped_index"].head())
        print(mapped_df[["abstime", "tcpseq", "sendkey"]].head())

        print("== DEBUG END ===")
# packetid
# know who is the client
# generate_direction_query
# we don't want to
        res = pd.merge(
            mapped_df, rawdf2, 
            left_on="mapped_index", 
            right_on="packetid",
            # right_index=True, 
            suffixes=self.suffixes, # how to suffix columns (sender/receiver)
            how="inner",
            indicator=True # adds a "_merge" suffix
        )

        # need to compute the owd depending on the direction right
        res['owd'] = res['abstime' + self.suffixes[1]] - res['abstime' + self.suffixes[0]]

        # print(res[["packetid", "mapped_index", "owd", "sendkey_snd", "sendkey_rcv"]])
        return res

    #def do_plot_owd(self, args):
    def plot(self, df_results, mptcpstream=None, **kwargs):
        """
        Ideally it should be mapped automatically
        For now plots only one direction but there could be a wrapper to plot forward owd, then backward OWDs
        Disclaimer: Keep in mind this assumes a perfect synchronization between nodes, i.e.,
        it relies on the pcap absolute time field.
        While this is true in discrete time simulators such as ns3


        Todo:
            it should be possible to cache intermediary results (computed owds)

        """
        # assert mptcpstream is not None, "parser should provide automatically this"

        # prepare a plot
        fig = plt.figure()
        axes = fig.gca()

        res = df_results
        print("columns", res.columns)

        print(res[["packetid", "mapped_index", 
            "sendkey" + self.suffixes[0], "sendkey" + self.suffixes[1],]])

        # need to compute the owd depending on the direction right
        # res['owd'] = res['abstime_y'] - res['abstime_x']
        # TODO groupby ('tcpstream', 'dest')

        pplot = res.owd.plot.line(
            # gca = get current axes (Axes), create one if necessary
            ax=axes,
            legend=True,
            # style="-o",
            grid=True,
            # xticks=tcpstreams["reltime"],
            # rotation for ticks
            # rot=45, 
            # lw=3
        )

        # TODO add units
        axes.set_xlabel("Time (s)")
        axes.set_ylabel("One Way Delay (s)")
        return fig



class MpTcpOneWayDelay(TcpOneWayDelay):
    """
    Same as TcpOneWayDelay but for several

    Todo:
        support skipping streams
    """

    def preprocess(self, main, mptcpstream=None, **kwargs):
        """
        This is trickier than in other modules: this plot generates intermediary results
        to compute OWDs. There results can be cached in which  case it's not necessary
        to load the original pcaps
 
        First we get the cachename associated with the two pcaps. If it's cached we load 
        directly this cache else we proceed as usual
        """
        cachename = self.get_cachename(kwargs.get("client_pcap"), kwargs.get("server_pcap"))
        # if we can't load that file from cache
        try:
            df = main.load_into_pandas(cachename)
            return df
        except Exception:
            log.debug("Could not load cahed results %s" % cachename)
        # if main.cache.is_cache_valid():
        #     pd.read_csv

        dataframes = super().preprocess(main, mptcpstream=mptcpstream, **kwargs)
        
        # we want to save results as a single file (easier to loader etc...)
        # so we concat ?
        # self.generate_owd_df(dataframes, cachename, **kwargs)
        df1, df2 = dataframes
        main_connection = data.MpTcpConnection.build_from_dataframe(df1, mptcpstream)

        # # du coup on a une liste
        mappings = data.mptcp_match_connection(rawdf2, main_connection)

        print("Found mappings %s" % mappings)
        # returned a dict
        # if mptcpstream not in mappings:
        #     print("Could not find ptcpstream %d in the first pcap" % mptcpstream)
        #     return 
        # print("Number of %d" % len(mappings[mptcpstream]))
        # print("#mappings=" len(mappings):
        if len(mappings) <= 0:
            print("Could not find a match in the second pcap for mptcpstream %d" % mptcpstream)
            return 


        # limit number of packets while testing 
        # HACK to process faster
        df1 = df1.head(limit)
        rawdf2 = rawdf2.head(limit)

        print("len(df1)=", len(df1), " len(rawdf2)=", len(rawdf2))
        # mappings
        mapped_connection, score = mappings[0]

        # some subflows may have been blocked by routing/firewall
        common_subflows = [] 
        for sf in main_connection.subflows:
            # if sf2 in 
            for sf2 in mapped_connection.subflows:
                if sf == sf2:
                    common_subflows.append((sf, sf2))
                    break

            # try:
            #     idx = mapped_connection.subflows.index(sf)
            #     sf2 = mapped_connection.subflows[idx]
            #     common_subflows.append((sf, sf2))

            # except ValueError:
            #     continue

        # common_subflows = set(mapped_connection.subflows, main_connection.subflows)
        print("common sf=%s", common_subflows)
        assert len(common_subflows) > 0, "Should be at least one common sf"
        # print(mappings)
        print("Found mappings %s" % mappings)
        return 
