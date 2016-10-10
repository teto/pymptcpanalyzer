#!/usr/bin/env python
# -*- coding: utf-8 -*-

import mptcpanalyzer.plot as plot
import mptcpanalyzer.data as core
import pandas as pd
import logging
import matplotlib.pyplot as plt
import os
import argparse


log = logging.getLogger(__name__)


class OneWayDelay(plot.Matplotlib):
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

    def __init__(self):
        super().__init__(preprocess_dataframes=False)


    def default_parser(self, *args, **kwargs):
        parser = super().default_parser( *args, required_nb_of_dataframes=2, mptcpstream=True, **kwargs)

        # parser.add_argument("host1", action="store", help="pcap captured on first host")
        # parser.add_argument("mptcpstreamid", action="store", type=int)

        # parser.add_argument("host2", action="store",
        #         help="Either a pcap or a csv file (in good format)."
        # )

        return parser

    #def do_plot_owd(self, args):
    def plot(self, rawdfs, mptcpstream=None, **kwargs):
        """
        Ideally it should be mapped automatically
        For now plots only one direction but there could be a wrapper to plot forward owd, then backward OWDs
        TODO should be moved as a plot
        This doesn't use "data"
        Disclaimer: Keep in mind this assumes a perfect synchronization between nodes, i.e.,
        it relies on the pcap absolute time field.
        While this is true in discrete time simulators such as ns3
        """
        assert mptcpstream is not None, "parser should provide automatically this"

        rawdf1, rawdf2 = rawdfs
        # args = parser.parse_args(shlex.split(args))
        # ds1 = main.load_into_pandas(args.client_input)
        # ds2 = main.load_into_pandas(args.server_input)
        # print("=== DS1 0==\n", ds1.dtypes)
        
        # Restrict dataset to mptcp connections of interest
        # ds1 = ds1[(ds1.mptcpstream == args.mptcp_client_id)]
        # ds2 = ds2[ds2.mptcpstream == args.mptcp_server_id]

        df1 = self.preprocess(rawdf1, mptcpstream=mptcpstream, **kwargs)
        # print("=== DS1 ==\n", ds1.dtypes)
        # now we take only the subset matching the conversation

        # limit number of packets while testing 
        limit = 100
        df1 = df1.head(limit)
        rawdf2 = rawdf2.head(limit)

        main_connection = core.MpTcpConnection.build_from_dataframe(df1, mptcpstream)

        # du coup on a une liste
        mappings = core.mptcp_match_connection(df1, rawdf2, main_connection)

        # print(mappings)
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
        assert len(common_subflows), "Should be one common sf"

        sf1, sf2 = common_subflows[0]
        # for now we just run the test on the most active subflow
        # this will return rawdf1 with an aditionnal "mapped_index" column that
        # correspond to 
        mapped_df = core.map_tcp_packets(rawdf1, rawdf2, sf1, sf2)
        mapped_df["mapped_index"]

        print(mapped_df)
        # print("Found %d valid mappings " % len(mappings))
        # print(mappings)
        # print("Host ips: ", args.host_ips)
        # dat = self.filter_ds(data, mptcpstream=args.mptcpstream, srcip=args.sender_ips)
        # ds1 = self.filter_ds(ds1, mptcpstream=args.mptcp_client_id, ipsrc=args.sender_ips)

        # TODO we should plot 2 graphs:
        # OWD with RTT (need to get ack as well based on tcp.nextseq ?) 
        # DeltaOWD
        # group = self.data[self.data.mptcpstream == mptcpstream]



        res = pd.merge(mapped_df, rawdf2, left_on="mapped_index", right_index=True, how="inner",
            indicator=True # adds a "_merge" suffix
        )
        
        # prepare a plot
        fig = plt.figure()
        axes = fig.gca()

        res['owd'] = res['abstime_y'] - res['abstime_x']

        # filename = "merge_%d_%d.csv" % (tcpstreamid_host0, tcpstreamid_host1)
        print(res.columns)
        res.to_csv(
            "backup.csv", 
            # columns=["owd", "abstime_x", "abstime_y", "packetid_x", "packetid_y", "tcpseq" ], 
            index=False,
            header=True,
            # sep=main.config["DEFAULT"]["delimiter"],
        )

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
        axes.set_xlabel("Time")
        axes.set_ylabel("One Way Delay")


        return fig

        ########################################
        ### this is never executed (legacy code)
        ########################################
        # see interesting tutorial 
        # http://pandas.pydata.org/pandas-docs/stable/merging.html
        # how=inner renvoie 0, les choix sont outer/left/right
        # ok ca marche mais faut faire gaffe aux datatypes
        for tcpstreamid_host0, tcpstreamid_host1, sf in mappings:
        
            # todo split dataset depending on soruce or destination
            print('sf',sf)
            # TODO add port/src/dst in case there are several subflows from a same interface
            tcpstream0 = ds1.query("tcpstream == @tcpstreamid_host0 and ipsrc == '%s'" % sf.ipsrc)
            print("toto")
            tcpstream1 = ds2.query("tcpstream == @tcpstreamid_host1 and ipsrc == '%s'" % sf.ipsrc)
            # # "indicator" shows from where originates 
            print("=== tcpseq ")
            print(tcpstream0.tcpseq.head(10))
            print("=== tcpseq ")
            print(tcpstream1.tcpseq.head(10))
                # tcpstream0 = ds1[ds1.tcpstream == tcpstreamid_host0]

            # TODO here we should merge on the 
            res = pd.merge(tcpstream0, tcpstream1, on="tcpseq", how="inner", indicator=True)
            print("========================================")
            # print(res.dtypes)
            print("nb of rtesults", len(res))
            # ensuite je dois soustraire les paquets
            # stop after first run


            # TODO creer un nouveau champ
            res['owd'] = res['abstime_y'] - res['abstime_x']

            filename = "merge_%d_%d.csv" % (tcpstreamid_host0, tcpstreamid_host1)
            res.to_csv(
                    filename, 
                    columns=["owd", "abstime_x", "abstime_y", "packetid_x", "packetid_y", "tcpseq" ], 
                    index=False,
                    header=True,
                    sep=main.config["DEFAULT"]["delimiter"],
            )

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
        axes.set_xlabel("Time")
        axes.set_ylabel("One Way Delay")
        # print("toto", type(pplot))

        ###  Correct legend for the linux 4 subflow case
        #############################################################
        h, l = axes.get_legend_handles_labels()

        # axes.legend([h[0], h[2]], ["Subflow 1", "Subflow 2"])
        # axes.legend([h[0], h[1]], ["Subflow 1", "Subflow 2"])
        print(h, l)

        return fig
