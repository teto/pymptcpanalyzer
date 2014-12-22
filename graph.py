#!/usr/bin/env python3
###########################################################
# author: Matthieu coudron , matthieu.coudron@lip6.fr
# this script requires wireshark (& gnuplot >4.6) to be installed
# http://stackoverflow.com/questions/11500469/plotting-columns-by-calling-their-header-with-gnuplot
import csv
import argparse
import sqlite3 as sql


graph_types = {
'mappings' : '',
'mptcp_rtt' : '',

} 


# def load_db_from_pcap
# def load_db_from_sqlite

class MptcpDatabase(object):
    """
    we want queries
    """

    con = None

    def __init__(self, db):
        self.con = sql.connect(db)
        self.con.row_factory = sql.Row

    def query(query):
        """
        query : string
        """
    # req = "SELECT * FROM connections WHERE sendkey != '' and recvkey != '' GROUP BY streamid"
        return con.execute(query)

    def plot_mappings(self, mptcp_stream):
        res = self.query("SELECT * FROM connections GROUP BY mptcpstream")

    def list_connections(self):
        res = self.query("SELECT * FROM connections GROUP BY mptcpstream")
        for row in res:
            print(res)

# csv.DictReader(csvfile)
# csvreader.fieldnames


def main():
    parser = argparse.ArgumentParser(
            description='Generate MPTCP stats & plots'
            )


    parser.add_argument("sqlite_file", action="store", help="file")
    parser.add_argument("mptcp_stream", action="store", help="identifier of the MPTCP stream")
    
    # parser.add_argument("pcap_file", action="store", help="file")
    subparsers = parser.add_subparsers(dest="subparser_name", title="Subparsers", help='sub-command help')
    
    # SubParser_mapping
    sp_mapping = subparsers.add_parser('mappings', help='To csv')
    # subparser_csv.add_argument('inputPcap', action="store", help="Input pcap")
    # subparser_csv.add_argument('output', nargs="?", action="store", help="csv filename")
    # subparser_csv.add_argument('--relative', action="store", help="set to export relative TCP seq number")

