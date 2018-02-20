import logging
import csv
import tempfile
import copy
import sqlite3 as sql


log = logging.getLogger(__name__)


class MpTcpUniflow:
    """
    Meant as 'unidirectional subflow'
    Identified by a stream number, ip/port src/dst
    """

    def __init__(self, tcpstream, ip4src, ip4dst, srcport, dstport, **kwargs):
        self.tcpstream = tcpstream
        self.ip4src = ip4src
        self.ip4dst = ip4dst
        self.srcport = srcport
        self.dstport = dstport

    @staticmethod
    def create_entry_from_row(row):
        """
        Because row is read only
        """
        # print(**row)
        # return MpTcpUniflow(row['tcpstream'], row['ip4src'], row['ip4dst'], srcport, dstport) 
        return MpTcpUniflow(**row) 
        #     'ip4src': row['ip4src'],
        #     'ip4dst': row['ip4dst'],
        #     'srcport': row['srcport'],
        #     'dstport': row['dstport'],
        #     'tcpstream': row['tcpstream'],
        # }

    def get_reverse_uniflow(self):
        rev = copy.deepcopy(self)

        rev.ip4src = self.ip4dst
        rev.ip4dst = self.ip4src
        rev.srcport = self.dstport
        rev.dstport = self.srcport
        return rev
        # row['srcport'], row['dstport'] = row['dstport'], row['srcport']

    def __tostring__(self):
        return self.ip4src + ":" + self.srcport + ' -> ' + self.ip4dst + ":" + self.ip4dst


class MpTcpDatabase:
    """
    we want queries
    """

    con = None
    cursor = None
    exported_fields = []

    def __init__(self, db):
        log.info('Opening db %s' % db)
        # detecting types apparently adds weird chars at the end of the file
        self.con = sql.connect(db, detect_types=False)
        self.con.row_factory = sql.Row

        self.cursor = self.con.cursor()

        # we could get them from sqlite but that seems easier
        self.exported_fields = load_fields_to_export_from_file("fields_to_export.json")

    # def query(query):
    #     """
    #     query : string
    #     """
    # # req = "SELECT * FROM connections WHERE sendkey != '' and recvkey != '' GROUP BY streamid"
    #     return self.cursor.execute(query)


    # def plot_subflows_as_datasets(self, mptcp_stream):
    #     # TODO first write header ?
    #     # print("fields to export:\n", fields_to_export)
    #     with open("test.dat", "w+") as f:
    #     # with tempfile.NamedTemporaryFile("w+", prefix="plot", delete=False) as f:
    #         # extrasaction
    #         writer = csv.writer(f, delimiter='|')
    #         # writer = csv.DictWriter(f, fieldnames=fields_to_export, delimiter='|')
    #         # write header
    #         # TODO retrieve names of the entry from SQLITE !

    #         # # subflow %s\n" % str(tcpstream)
    #         nb_records = 0

    #         for sf in self.list_subflows(mptcp_stream):
    #             # print("tcpstream", tcpstream)
    #             # in conjunction with column header, could set pot titles
    #             # f.write("tcpstream")
    #             previous_unidirectional_flow = None
    #             for row in self._plot_subflow_mappings(int(sf['tcpstream'])):

    #                 # if nb_records == 0:
    #                 #     fields_to_export = row.keys()       
    #                 #     f.write(build_csv_header_from_list_of_fields(fields_to_export, '|'))
    #                 temp = (row['ip4src'], row['ip4dst'], row['ip6src'], row['ip6dst'],)
    #                 if not previous_unidirectional_flow:
    #                     previous_unidirectional_flow = temp
    #                     f.write(build_csv_header_from_list_of_fields(self.exported_fields, '|'))
    #                 elif temp != previous_unidirectional_flow:
    #                     previous_unidirectional_flow = temp
    #                     f.write("\n\n")
    #                     f.write(build_csv_header_from_list_of_fields(self.exported_fields, '|'))

    #                 # print(dir(row))

    #                 # if writer.writerow(row) creates a problem, replace it by the 2
    #                 # following lines
    #                 # lolita = '|'.join([row[key] for key in row.keys()]) + "\n"
    #                 # f.write(lolita)
    #                 writer.writerow(row)

    #                 nb_records = nb_records + 1

    #         log.debug("found %d records" % nb_records)
    #         return f.name

    # ip4src="ip4src",
    def export_subflow_to_csv(self, filename, tcpstream, append=False):
        """
        export to 'filename' - in csv format - the   
        Set append to True to write at the end of the file 
        (in order to write data sets)
        """
        with open(filename, "w+") as f:
            writer = csv.writer(f, delimiter='|')

            f.write(build_csv_header_from_list_of_fields(self.exported_fields, '|'))

            q = "SELECT * FROM connections WHERE tcpstream=={tcpstream} ORDER BY reltime".format(
                tcpstream=tcpstream,
                # ip4src=ip4src,
            ) 

            log.info(q)
            res = self.cursor.execute(q)
            log.debug("nb of results:", res.rowcount)

            for row in res:
                writer.writerow(row)

    # ipdst, srcport, dstport
    def export_uniflow_to_csv(self, filename, uniflow,):

        assert (isinstance(uniflow, MpTcpUniflow))

        with open(filename, "w+") as f:
            print("writing to > ", filename)

            f.write(build_csv_header_from_list_of_fields(self.exported_fields, '|'))
            writer = csv.writer(f, delimiter='|')

    #     q = "SELECT * FROM connections WHERE (ip4src==? OR ip) ORDER BY ip4src, ip6src, ip6src, ip6dst", (tcpstream,)
            q = "SELECT * FROM connections WHERE tcpstream=={tcpstream} AND ip4src='{ip4src}' ORDER BY reltime".format(
                tcpstream=uniflow.tcpstream,
                ip4src=uniflow.ip4src,
            )
        # don't forget to write headers
        # TODO     writer = csv.DictWriter(f, fieldnames=fields_to_export, delimiter='|')
            print(q)
            res = self.cursor.execute(q)
            # print("nb of results:", res.rowcount)

            for row in res:
                writer.writerow(row)
    #     lol
    #     """

    #     ipsrc=ipsrc


    def list_subflows(self, mptcp_stream):
        """
        Return 3 lists:
        2 lists of unidirectional flows 
        characteristics registered in a dict like: 
        ip4src,ip4dst,srcport,dstport, tcpstream
        and a list of the tcpstream

        Generator
        mptcp.master
        tcp.options.mptcp.expected_token
        """
        master = None
        client_uniflows = []
        server_uniflows = []
        tcpstreams = []

        # export ca
        # first find 
        # tcp flags == 2 => SYN only
        # we want the master first
        # GROUP BY tcpstream
        # AND expectedtoken IS NOT NULL 
        # depending on the wireshark version or sqlite , the tcflags don't seem
        # to be imported the same way ?
        q = "SELECT * FROM connections WHERE mptcpstream==%s "
        " and tcpflags==%s ORDER BY master" % (mptcp_stream, "0x00000002")

        log.info(q)
        res = self.cursor.execute(q)
        for row in res:

            entry = MpTcpUniflow.create_entry_from_row(row)

            # print(str(row))
            if row['master']:
                master = entry
                client_uniflows.append(master)
            elif row['recvtok'] == master['expectedtoken']:
                client_uniflows.append(entry)
            # else:
            #     server_uniflows.append(object)

        # to get server uniflows, we just need to reverse the previous ones ipsrc, and dest
        # for uniflow in client_uniflows:
        #     row = row.copy()
        #     row['ip4src'], row['ip4dst'] = row['ip4dst'], row['ip4src']
        #     row['srcport'], row['dstport'] = row['dstport'], row['srcport']
        #     # print("after:", row)
        #     server_uniflows.append(row)

        return client_uniflows, server_uniflows, tcpstreams

        # res = self.cursor.execute("SELECT * FROM connections WHERE mptcpstream==? GROUP BY tcpstream", (mptcp_stream,))
        # that does not work
        # for row in res:
        #     print("row", row["tcpstream"])
        #     yield row
        # ["tcpstream"])
        # subflows = [int(row["tcpstream"]) for row in res]
        # return subflows

    def list_mptcp_connections(self):
        """
        Returns a list of integer
        """
        res = self.cursor.execute("SELECT * FROM connections GROUP BY mptcpstream ORDER BY CAST(mptcpstream as INT)")
        # for row in res:
        #     yield row
        connections = [int(row["mptcpstream"]) for row in res]
        return connections

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
