#!/usr/bin/env python
# -*- coding: utf-8 -*-

import mptcpanalyzer.plot as plot


class MappingVsAck(plot.Plot):

    stream = None

    def _complete_parser(self, parser):
        parser.add_argument("mptcp_stream", action="store", type=int, help="identifier of the MPTCP stream")

    def get_client_uniflow_filename(self, id):
        # os.join.path()
        return self.output_folder + "/" + "client_" + str(id) + ".csv"

    def init(self, args):
        stream = args.mptcp_stream
        print("mptcp_stream", stream)

        clients, server, tcpstreams = self.db.list_subflows(stream)

        for id, client in enumerate(clients):
            output = self.output_folder + str(id)

            client_filename = self.get_client_uniflow_filename(id)
            server_filename = self.get_server_uniflow_filename(id)

            self.db.export_uniflow_to_csv(client_filename, client)
            self.db.export_uniflow_to_csv(server_filename, client.get_reverse_uniflow())
# client_file=self.get_server_uniflow_filename(id), server
            self._call_gnuplot("plots/mappings/mappings_and_ack.plot", output, nb_of_subflows=len(clients))
        # genere les graphs

        # a la fin je pourrais les monter via une commande "montage"

    def generate(self):
        pass
        # self.db.list_subflows()
        # self.db.export_subflow_to_file

# **kwargs
p = MappingVsAck()
p.generate()
