#!/usr/bin/env python
# -*- coding: utf-8 -*-

import mptcpanalyzer.plot as plot


class RelativeDsn(plot.Plot):

    stream = None

    # TODO I could do this for both directions
    def init(self, args):
        """
        """
        parser = self.default_parser()
        args = parser.parse_args(args)

        self.stream = args.mptcp_stream

    def generate(self):
        """
        """
        output = self.output_folder + "/out.png"
        clients, server, tcpstreams = self.db.list_subflows(self.stream)

        for id, client in enumerate(clients, start=1):

            client_filename = self.get_client_uniflow_filename(id)
            server_filename = self.get_server_uniflow_filename(id)

            self.db.export_uniflow_to_csv(client_filename, client)
            self.db.export_uniflow_to_csv(server_filename, client.get_reverse_uniflow())
# client_file=self.get_server_uniflow_filename(id), server

        self._call_gnuplot("plots/dsn/dsn_and_ack.plot", output, nb_of_subflows=len(clients))
        return True, output
        # genere les graphs

        # a la fin je pourrais les monter via une commande "montage"
        # self.db.list_subflows()
        # self.db.export_subflow_to_file

# **kwargs
# p = MappingVsAck()
# p.generate()
