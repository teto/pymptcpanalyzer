#!/usr/bin/env python
# -*- coding: utf-8 -*-
import logging
import csv
import subprocess
import sqlite3 as sql

# from core import get_basename
from mptcpanalyzer.core import build_csv_header_from_list_of_fields 
from mptcpanalyzer import fields_dict, fields_to_export, get_basename

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)
log.addHandler(logging.StreamHandler())


class MpTcpDatabase:
    """
    we want queries
    """

    con = None
    cursor = None

    def __init__(self, db):
        self.con = sql.connect(db)
        self.con.row_factory = sql.Row

        self.cursor = self.con.cursor()

    # def query(query):
    #     """
    #     query : string
    #     """
    # # req = "SELECT * FROM connections WHERE sendkey != '' and recvkey != '' GROUP BY streamid"
    #     return self.cursor.execute(query)

    def _plot_subflow_info(self, tcpstream):
        """
        """
        res = self.cursor.execute("SELECT * FROM connections WHERE tcpstream==? AND mapping_length > 0 ORDER BY packetid", (str(tcpstream)))

        for row in res:
            # print(row.keys())
            yield row

    def plot_mappings(self, mptcp_stream):
        # or "ORDER BY"

        # TODO first write header ?
        print("fields to export:\n", fields_to_export)
        with open("test.dat", "w+") as f:
            # extrasaction
            writer = csv.writer(f, delimiter='|')
            # writer = csv.DictWriter(f, fieldnames=fields_to_export, delimiter='|')
            # write header
            f.write(build_csv_header_from_list_of_fields(fields_to_export, '|'))

            # # subflow %s\n" % str(tcpstream)

            for tcpstream in self.list_subflows(mptcp_stream):

                for i in self._plot_subflow_info():
                    writer.writerow(i)
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
        subflows = [int(row["tcpstream"]) for row in res]
            # print("row", row["tcpstream"])

        return subflows

    def list_connections(self):
        res = self.query("SELECT * FROM connections GROUP BY mptcpstream")
        for row in res:
            print(res)


# maybe those ones can be removed

# replace DISTINCT by groupby
# TODO rename to list master subflows
def list_master_subflows(db):
    """
    Only supports ipv4 to simplify things
    Returns 2 dictionaries of MPTCP connections: 
        - saw start and end of connection
        - only saw the start
    Fields should be iterable
    """
    # filter MP_CAPABLE and MP_JOIN suboptions
    # or DATA_FIN (DSS <=> subtype 2)

    # print(output.decode('utf-8'))
    # convert_csv_to_sql("connections.csv","connect.sqlite","connections")
    # exit()
    # input=initCommand.encode(),
    mptcp_con = []  # dict({})
    con = sql.connect(db)
    con.row_factory = sql.Row
    # cur = con.cursor();
    # stream,src,dst,srcport,dstport should compute 
    # TODO use GROUP BY instead of distinct ?
    # TODO order by time
    req = "SELECT * FROM connections WHERE sendkey != '' and recvkey != '' GROUP BY streamid"
    res = con.execute(req)

    for row in res:
        mptcp_con.append( 
            dict({
                "recvkey": row['recvkey'],
                "sendkey": row['sendkey'],
                "subflows": [row['streamid']]
            })
        )
        print("tcp stream ", row['streamid'], " sendkey", row["sendkey"], "recvkey", row["recvkey"])
        # mptcp_con

    return mptcp_con
    # log.info("command returned %d results"%cur.rowcount)

# #mptcp_connections,
# def list_subflows(db):
#     """
#     """
#     sql_con = sql.connect(db)
#     sql_con.row_factory = sql.Row

#     # filter MP_JOIN with SYN ONLY
#     # get token 
#     res = sql_con.execute("SELECT * FROM connections WHERE recvtok != '' GROUP BY streamid");
#     # 
#     # for con in mptcp_connections:
#     return res;


def export_connection_to_(db, mptcp_stream):
    """
    Retrieves
    """

# def list_mptcp_connections(db):
#     mptcp_connections = []
#     master_subflows = list_master_subflows(db)
#     #master_subflows
#     subflows = list_subflows ( db)

#     # map subflows to their respective master connection
#     # use .items() to loop through a dict
#     # for con in master_subflows:
#     #     dump_mptcp_connection(con)

#     # map subflows to their respective master connection
#     for row in subflows:
#         pass
