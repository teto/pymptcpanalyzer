#!/usr/bin/env python3
###########################################################
# author: Matthieu coudron , matthieu.coudron@lip6.fr
# this script requires wireshark (& gnuplot >4.6) to be installed
# http://stackoverflow.com/questions/11500469/plotting-columns-by-calling-their-header-with-gnuplot
import csv
import sys
import argparse
import sqlite3 as sql
from mptcpanalyzer.core import build_csv_header_from_list_of_fields
from mptcpanalyzer import fields_to_export

# graph_types = {
# 'mappings' : '',
# 'mptcp_rtt' : '',

# } 


# def load_db_from_pcap
# def load_db_from_sqlite

class MptcpDatabase(object):
    """
    we want queries
    """

    con = None
    cursor = None

    def __init__(self, db):
        self.con = sql.connect(db)
        self.con.row_factory = sql.Row

        self.cursor = self.con.cursor()

    def query(query):
        """
        query : string
        """
    # req = "SELECT * FROM connections WHERE sendkey != '' and recvkey != '' GROUP BY streamid"
        return self.cursor.execute(query)

    def plot_mappings(self, mptcp_stream):
        # or "ORDER BY"

        
        # TODO first write header ?
        # saved = 
        
        # subflow_ids = 
        
        print( "fields to export:\n", fields_to_export )
        with open("test.dat","w+") as f:
            # extrasaction
            writer = csv.writer(f, delimiter='|')
            # writer = csv.DictWriter(f, fieldnames=fields_to_export, delimiter='|')
            # write header
            f.write(build_csv_header_from_list_of_fields(fields_to_export, '|'))

            # # subflow %s\n" % str(tcpstream)

            for tcpstream in self.list_subflows(mptcp_stream):

                res = self.cursor.execute("SELECT * FROM connections WHERE tcpstream==? AND mapping_length > 0 ORDER BY packetid", (str(tcpstream)))

                
                for row in res:
                    # print(row.keys())
                    writer.writerow(row)

                # TODO separate datasets; give title
                # TODO it conditionnally
                f.write("\n\n")
                    # writer.writerows(res)
                # # if row["tcpstream"] != saved:
                #     for key in row.keys():

                #     print(dir(row))
                    # f.write(row[])



    def list_subflows(self, mptcp_stream):
        res = self.cursor.execute("SELECT * FROM connections WHERE mptcpstream==? GROUP BY tcpstream", (mptcp_stream,))
        subflows=[ int(row["tcpstream"]) for row in res ]
            # print("row", row["tcpstream"])
        
        return subflows

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
    sp_list_sf = subparsers.add_parser('list_subflows', help='To csv')
    sp_list_sf = subparsers.add_parser('plot', help='To csv')
    # sp_list_sf = sp_list_sf.set_defaults(func=list_subflows)

    # subparser_csv.add_argument('inputPcap', action="store", help="Input pcap")
    # subparser_csv.add_argument('output', nargs="?", action="store", help="csv filename")
    # subparser_csv.add_argument('--relative', action="store", help="set to export relative TCP seq number")

    args = parser.parse_args(sys.argv[1:])

    db = MptcpDatabase(args.sqlite_file)

    if args.subparser_name == "list_subflows":
    # if args.subparser_name == "pcap2csv":
        subflows = db.list_subflows(args.mptcp_stream)
        for sf in subflows:
            print( sf )
    elif args.subparser_name == "plot":
        db.plot_mappings(args.mptcp_stream)
    else:
        print("unknown command")


if __name__ == '__main__':
    main()