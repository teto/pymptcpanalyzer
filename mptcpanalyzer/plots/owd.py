#!/usr/bin/env python
# -*- coding: utf-8 -*-

import mptcpanalyzer.plot as plot
import mptcpanalyzer.data as core
import pandas as pd
import logging
import matplotlib.pyplot as plt
import os

log = logging.getLogger("mptcpanalyzer")

class OneWayDelay()

    def default_parser(self):
        #parser = super().default_parser()
        parser = argparse.ArgumentParser(
                description='Generate MPTCP stats & plots'
                )
        # client = parser.add_argument_group("Client data")

        parser.add_argument("client_input", action="store",
                help="Either a pcap or a csv file (in good format)."
                )
        parser.add_argument("mptcp_client_id", action="store", type=int)

        parser.add_argument("server_input", action="store",
                help="Either a pcap or a csv file (in good format)."
                )
        parser.add_argument("mptcp_server_id", action="store", type=int)

        parser.add_argument("host_ips", nargs="+",
                help=("List here ips of one of the 2 hosts so that the program can"
                    "deduce the flow directions.")
                )
        return parser

    #def do_plot_owd(self, args):
    def _generate_plot(self, data, args):
        """
        TODO should be moved as a plot
        This doesn't use "data"
        Disclaimer: Keep in mind this assumes a perfect synchronization between nodes, i.e.,
        it relies on the pcap absolute time field.
        While this is true in discrete time simulators such as ns3
        """
        # it arrives already parsed
        # try:
        #     # args = parser.parse_args( shlex.split(field + ' ' + args))
        #     args, unknown = parser.parse_known_args(shlex.split(args))
        # except SystemExit:
        #     return

        # args = parser.parse_args(shlex.split(args))
        ds1 = core.load_into_pandas(args.client_input)
        ds2 = core.load_into_pandas(args.server_input)
        # print("=== DS1 0==\n", ds1.dtypes)
        
        # Restrict dataset to mptcp connections of interest
        ds1 = ds1[(ds1.mptcpstream == args.mptcp_client_id)]
                
        ds2 = ds2[ds2.mptcpstream == args.mptcp_server_id]


        # print("=== DS1 ==\n", ds1.dtypes)
        # now we take only the subset matching the conversation
        mappings = core.map_subflows_between_2_datasets(ds1, ds2)
        print("Found %d valid mappings " % len(mappings))
        print(mappings)
        
        print("Host ips: ", args.host_ips)

        # dat = self.filter_ds(data, mptcpstream=args.mptcpstream, srcip=args.sender_ips)
        
        pattern = ' ipsrc == '
        pattern += ' or ipsrc == '.join(args.host_ips)

        print(pattern)
        # TODO we should plot 2 graphs:
        # OWD with RTT (need to get ack as well based on tcp.nextseq ?) 
        # DeltaOWD
        # group = self.data[self.data.mptcpstream == mptcpstream]
        
        # prepare a plot

        fig = plt.figure()

        axes = fig.gca()
        # see interesting tutorial 
        # http://pandas.pydata.org/pandas-docs/stable/merging.html
        # how=inner renvoie 0, les choix sont outer/left/right
        # ok ca marche mais faut faire gaffe aux datatypes
        for tcpstreamid_host0, tcpstreamid_host1, sf in mappings:
        
            # todo split dataset depending on soruce or destination
            print('sf',sf)
            tcpstream0 = ds1.query("tcpstream == @tcpstreamid_host0 and ipsrc == '%s'" % sf.ipsrc)
            print("toto")
            tcpstream1 = ds2.query("tcpstream == @tcpstreamid_host1 and ipsrc == '%s'" % sf.ipsrc)
            # # "indicator" shows from where originates 
            print("=== tcpseq ")
            print(tcpstream0.tcpseq.head(10))
            print("=== tcpseq ")
            print(tcpstream1.tcpseq.head(10))
                # tcpstream0 = ds1[ds1.tcpstream == tcpstreamid_host0]

            res = pd.merge(tcpstream0, tcpstream1, on="tcpseq", how="inner", indicator=True)
            print("========================================")
            # print(res.dtypes)
            print("nb of rtesults", len(res))
            # ensuite je dois soustraire les paquets
            # stop after first run


            # TODO creer un nouveau champ
            res['owd'] = res['abstime_y'] - res['abstime_x']

            filename = "merge_%d_%d.csv" % (tcpstreamid_host0, tcpstreamid_host1)
            res.to_csv(filename, columns=["owd", "abstime_x", "abstime_y", "packetid_x", "packetid_y"  ], sep=delimiter)


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

            # res.to_csv("temp.csv", sep=delimiter)
            # stop after first run

        # print(dir(axes))
        axes.set_xlabel("Time")
        axes.set_ylabel("OWD")
        # print("toto", type(pplot))

        ###  Correct legend for the linux 4 subflow case
        #############################################################
        h, l = axes.get_legend_handles_labels()

        # axes.legend([h[0], h[2]], ["Subflow 1", "Subflow 2"])
        # axes.legend([h[0], h[1]], ["Subflow 1", "Subflow 2"])
        print(h, l)

        args.out = os.path.join(os.getcwd(), "owd.png")
        print("Saving into %s" % (args.out))
        fig.savefig(args.out)
        return True

        ## JUSTE pour les tests, sinon commenter ce qu'il y a au dessus
        # "indicator" shows from where originates 
# %s "%(sf.ipsrc, ))
        tcpstream0 = ds1.query("tcpstream == 0 and ipsrc == '10.1.0.1' ") 
        tcpstream1 = ds2.query("tcpstream == 0 and ipsrc == '10.1.0.1' ")
        print("=== tcpseq ")
        print(tcpstream0.tcpseq.head(10))
        print("=== tcpseq ")
        print(tcpstream1.tcpseq.head(10))
        # print("========================================")
        # print(tcpstream0)
        # print("========================================")
        # print(tcpstream1)
        # res = pd.merge(tcpstream0, tcpstream1, on="tcpseq", how="inner", indicator=True)
        res = pd.merge(tcpstream0, tcpstream1, on="tcpseq", how="inner", indicator=True)
        print("========================================")
        # print(res.dtypes)
        print("nb of rtesults", len(res))
        # ensuite je dois soustraire les paquets
        # stop after first run
        # we need .copy else we get
        # A value is trying to be set on a copy of a slice from a DataFrame.
# Try using .loc[row_indexer,col_indexer] = value instead

# See the caveats in the documentation: http://pandas.pydata.org/pandas-docs/stable/indexing.html#indexing-view-versus-copy
# if __name__ == '__main__':
        # r2 = r[["tcpseq","abstime_x","abstime_y"]].copy()
        # r2['diff'] = r2['abstime_y'] - r2['abstime_x']
        # Need to create a new table that 
# df3 = df1[['Lat1', 'Lon1']]
# df3['tp1-tp2'] = df1.tp1 - df2.tp2
        return 