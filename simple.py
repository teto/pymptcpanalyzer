#!/usr/bin/env python3
###########################################################
# author: Matthieu coudron , matthieu.coudron@lip6.fr
# this script requires wireshark (& gnuplot) to be installed
#
# the aim of this script is to plot window/acks
# at both the MPTCP connection and the subflow level
# (for now 1 MPTCP communication => 1 subflow)
#
# csv module doc: https://docs.python.org/3/library/csv.html

# mptcptrace syntax is not easy to follow. for now we assume that
# - {c2s/s2c}_seq_{id}.csv displays:
#   seconds+usec/ack/subflowId(="color")/0/0/-1
# - connection_{id}.csv 
#    subflowId,IPversion,sport,dport,saddr,daddr
# - {c2s/s2c}_acksize_{id}.csv
#    time/ack/id/0/0/-1

import argparse
import csv
import os
import shutil
#import querycsv as q
import subprocess
import logging
import sys
import sqlite3 as sql
import hashlib # to use sha1


log = logging.getLogger( __name__)
log.setLevel(logging.DEBUG)
log.addHandler(logging.StreamHandler())

### CONFIG
#########################
plotsDir     = "plots"
subflowsList = "connection_0.csv"
gnuplotScript        = "/home/teto/mptcptrace/res/scripts/gnuplot/sf_vs_master.plot"
# TODO pass as cl arg
inputPcap = "/home/teto/pcaps/mptcp167.1407349533.bmL/dump_strip.pcap"
mptcpSeqCsv = "/home/teto/ns3/c2s_seq_0.csv"
# where to save subflow statistics (into a CSV file)
subflowSeqCsv = "/home/teto/subflowSeq.csv"
tableName = "connections"
# -o force an option, else we can set a profile like -C <profileName>
tshark_exe = "~/wireshark/tshark"

# first erase previous data
if os.path.isdir(plotsDir):
    shutil.rmtree(plotsDir)

os.mkdir(plotsDir)
#os.chdir(plotsDir)



# dict to create distinct and understandable csv/sql keys
fields_dict = {
    "packetid"  : "frame.number",
    "time"  : "frame.time",
    "time_delta"  : "frame.time_delta",
    "ipsrc" : "ip.src",
    "ipdst" : "ip.dst",
    "srcport" : "tcp.srcport",
    "tcpstream"  : "tcp.stream",
    "mptcpstream"  : "mptcp.stream", # tcp.options.
    "dstport"   : "tcp.dstport",
    
    "sendkey" : "tcp.options.mptcp.sendkey",
    "recvkey" : "tcp.options.mptcp.recvkey",
    # sent in MP_JOIN s
    "recvtok"  : "tcp.options.mptcp.recvtok",
    # sent in MP_JOIN SYN/ACK
    "sendtruncmac" : "tcp.options.mptcp.sendtruncmac",
    "datafin" : "tcp.options.mptcp.datafin.flag",
    # be careful this outputs subtype0,subtype1,... etc.. so it can introduce "," that 
    # prevents csv parsing if not correctly delimited
    "subtype" : "tcp.options.mptcp.subtype",
    "tcpflags" : "tcp.flags",
    # mptcp level DATASEQ ...
    "mapping_dsn" : "tcp.options.mptcp.dataseqno",
    # ... mapped to subflow level seq
    "mapping_ssn" : "tcp.options.mptcp.subflowseqno",
    "mapping_length" : "tcp.options.mptcp.datalvllen",
    # converts SSN to DSN
    "ssn_to_dsn" : "tcp.options.mptcp.seq2dsn",
    "master" : "tcp.options.mptcp.master",
    "tcpseq" : "tcp.seq",
    "unmapped" : "tcp.options.mptcp.unmapped",
}


fields_to_export = ("packetid","time_delta",
                #"ipsrc","ipdst","srcport",
                "tcpstream","mptcpstream",
                "subtype",
                # "datafin",
                # "recvtok","sendtruncmac",
                "recvkey","sendkey",
                "tcpseq",
                "mapping_ssn",
                # "mapping_length",
                # "mapping_dsn",
                "ssn_to_dsn",
                # "unmapped",
                # "master"
                )


def export_all_subflows_data():
    # # find all connections in that (ideally enabled via -l)
    # with open(subflowsList) as csvfile:
    #   #, quotechar='|'
    #   # csv.reader
    #   # csv.DictReader ( fieldnames=)
    #   subflowReader = csv.DictReader(csvfile, delimiter=',')
    #   for id,subflow in enumerate(subflowReader):
    #       #print(subflow)
    #       export_subflow_data(inputPcap,subflowSeqCsv,filter)
    #       # todo filter from tshark
            
    # # finally I run gnuplot passing the names of the different files
    # # pseudocode
    # # todo have a loop in gnuplot ? in case there are several subflows ?
    # cmd= "gnuplot -e \"mptcpSeqCsv='{mptcpData}';subflowSeqCsv='{subflowSeq}'\" {script} ".format(
    #       script=gnuplotScript,
    #       mptcpData=mptcpSeqCsv,
    #       subflowSeq=subflowSeqCsv
    #   )

    # print(cmd)
    # os.system(cmd)
    pass

#tshark export_fields
def tshark_export_fields(inputFilename,fields_to_export,filter=None,outputFilename=None,relative_sequence_numbers=True):
    """
    inputFilename should be pcap filename
    fields should be iterable (tuple, list ...)
    returns outout as a string
    """
    def convert_into_tshark_field_list(fields):

        return ' -e ' + ' -e '.join([ fields_dict[x] for x in fields ])
    # fields that tshark should export
    # tcp.seq / tcp.ack / ip.src / frame.number / frame.number / frame.time
    # exhaustive list https://www.wireshark.org/docs/dfref/f/frame.html
    # tcp.options.mptcp.subtype == 2 => DSS (0 => MP-CAPABLE)
    # to filter connection
    filter = '-2 -R "%s"'%(filter) if filter else ''


    options = ' -o tcp.relative_sequence_numbers:TRUE' if relative_sequence_numbers else ''

    # for some unknown reasons, -Y does not work so I use -2 -R instead
    # 
    cmd="{tsharkBinary} {tsharkOptions} -n {filterExpression} -r {inputPcap} -T fields {fieldsExpanded} -E separator=, -E quote=d ".format(
                tsharkBinary=tshark_exe,
                tsharkOptions=options,
                inputPcap=inputFilename,
                outputCsv=outputFilename,
                fieldsExpanded=convert_into_tshark_field_list(fields_to_export),
                filterExpression=filter
                )

    log.info(cmd)

    #https://docs.python.org/3/library/subprocess.html#subprocess.check_output
    output = subprocess.check_output(cmd, shell=True);
    # os.system(cmd)
    # except CalledProcessError as e:
    return output


def build_csv_header_from_list_of_fields(fields):
    """
    fields should be iterable
    Returns "field0,field1,..."
    """
    # def strip_fields(fields):
    #   return [ field.split('.')[-1] for field in fields ] 
    # return (','.join( strip_fields(fields)) + '\n'  ).encode()
    return ','.join( fields ) + '\n'


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
    req = "SELECT ipsrc,streamid,sendkey,recvkey FROM connections WHERE sendkey != '' and recvkey != '' GROUP BY streamid"
    res = con.execute(req);
    for row in res:
        mptcp_con.append( 
            dict({
                "recvkey" : row['recvkey'],
                "sendkey" : row['sendkey'],
                "subflows" : [ row['streamid'] ]
            })
            
            )
        print("tcp stream ", row['streamid'], " sendkey", row["sendkey"],"recvkey", row["recvkey"])
        # mptcp_con

    return mptcp_con
    # log.info("command returned %d results"%cur.rowcount)

#mptcp_connections,
def list_subflows( db):
    """
    """
    sql_con = sql.connect(db)
    sql_con.row_factory = sql.Row

    # filter MP_JOIN with SYN ONLY
    # get token 
    res = sql_con.execute("SELECT * FROM connections WHERE recvtok != '' GROUP BY streamid");
    
    # 
    # for con in mptcp_connections:
    return res;



def list_mptcp_connections(db):
    mptcp_connections = []
    master_subflows = list_master_subflows(db)
    #master_subflows
    subflows = list_subflows ( db)

    # map subflows to their respective master connection
    # use .items() to loop through a dict
    # for con in master_subflows:
    #     dump_mptcp_connection(con)

    # map subflows to their respective master connection
    for row in subflows:
        pass

# def run_query():
# receiver token 3217261719
# bytes()
def convert_pcap_to_sql(inputPcap,outputDb):



    log.info("Converting pcap [{pcap}] to sqlite database [{db}]".format(
            pcap=inputPcap,
            db=outputDb
        ))

    csv_filename = get_basename(outputDb, "csv")
    convert_pcap_to_csv(inputPcap, csv_filename)

    convert_csv_to_sql(csv_filename, outputDb, tableName)

    # return out

def get_basename( fullname, ext):
    return  os.path.splitext(os.path.basename(fullname))[0] + "." + ext


def convert_pcap_to_csv(inputPcap,outputCsv,tcp_relative_seq=True):
    """
    """
    log.info("Converting pcap [{pcap}] to csv [{db}]".format(
            pcap=inputPcap,
            db=outputCsv
        ))



    # TODO should export everything along with TCP acks
    # ands convert some parts of the filter into an SQL request
    filter="mptcp.stream == 0"



    output = build_csv_header_from_list_of_fields(fields_to_export).encode()
    print(output);
    output += tshark_export_fields(inputPcap,fields_to_export,filter)

    # q.
    # load this into a csv reader
    # with
    # could filter
    log.info("Writing to file")
    with open(outputCsv,"w") as f:
        f.write(output.decode())




# Ideally I would have liked to rely on some external library like
# querycsv, csvkit etc... but they all seem broken in one way or another
# https://docs.python.org/3.4/library/sqlite3.html
def convert_csv_to_sql(csv_filename,database,table_name):
    # sqlite3
    # 
    # > .separator ","
    # > .import test.csv TEST
    """
    csv_filename
    csv_content should be a string
    Then you can run SQL commands via SQLite Manager (firefox addon)
    """
    tempInitFilename="init.sql"

    log.info("Converting csv to sqlite table {table} into {db}".format(
            table=table_name,
            db=database
        ))
    # db = sqlite.connect(database)
    # csv_filename
    initCommand=(
        "DROP TABLE IF EXISTS {table};\n"
        ".separator '{separator}'\n"
            
            ".import {csvFile} {table}\n").format(
            separator=",",
            csvFile=csv_filename,
            table=table_name
            )

    log.info("Creating %s"%tempInitFilename)
    with open(tempInitFilename,"w+") as f:
        f.write(initCommand)

    cmd= "sqlite3 -init {initFilename} {db}".format(
        initFilename=tempInitFilename,
        db=database
        )

    # cmd="sqlite3"
    # tempInitFilename      
    log.info("Running command:\n%s"% cmd)
    # input=initCommand.encode(),
    output = subprocess.check_output(  cmd ,input=".exit".encode(), shell=True)
    


def main():

    # https://docs.python.org/3/library/argparse.html#module-argparse
    parser = argparse.ArgumentParser(
            description='Generate MPTCP stats & plots'
            )

    # readconfigFromFile
    #argparse.FileType('r')
    # parser.add_argument('xpconfig', default="tests.ini", action="store", type=str,  help="Config filename. Describe experiment settings")

    # parser.add_argument('inputPcap', action="store", help="src IP")
    
    subparsers = parser.add_subparsers(dest="subparser_name", title="Subparsers", help='sub-command help')
    
    subparser_csv = subparsers.add_parser('pcap2csv', help='To csv')
    subparser_csv.add_argument('inputPcap', action="store", help="Input pcap")
    subparser_csv.add_argument('output', nargs="?", action="store", help="csv filename")
    subparser_csv.add_argument('--relative', action="store", help="set to export relative TCP seq number")


    # List MPTCP connections and subflows
    subparser_sql = subparsers.add_parser('csv2sql', help='Tosql')
    subparser_sql.add_argument('inputCsv', action="store", help="Input Csv")
    subparser_sql.add_argument('output', nargs="?", action="store", help="db filename")

    #parent
    subparser_list = subparsers.add_parser('list', help='List MPTCP connections and subflows and saves them to a csv file',aliases=["l"])
    subparser_list.add_argument('db', action="store", help="Input sql")
    # subparser_list.add_argument('outputCsv',  action="store", help="sql filename")

    subparser_query = subparsers.add_parser('query', help='Run an SQL query',aliases=["q"])
    subparser_query.add_argument('db', action="store", help="could be csv or sql")
    # parser_list.add_argument('outputCsv', action="store",  help="src IP")

    subparser_plot = subparsers.add_parser('plot', help='Run an SQL query',aliases=["q"])
    subparser_plot.add_argument('connectionCsv', action="store", help="Csv file that describes connection")

    subparser_plot.add_argument('type', action="store", choices=["seq"], help="type of plot")

    # parser.add_argument('srcIp', action="store", help="src IP")
    # parser.add_argument('dstIp', action="store", help="dst IP" ) 
    # parser.add_argument('--nat', action="store", help="world") #nat_parser.print_help() )

    args = parser.parse_args( sys.argv[1:] )
    if args.subparser_name == "list":
        list_mptcp_connections(args.db)
        # if(args.tosql):
        #   convert_csv_to_sql( "connections.csv",args.tosql,"connections")

    elif args.subparser_name == "query":
        print("query")
    elif args.subparser_name == "pcap2csv":
        inputFilename = args.inputPcap
        outputFilename = args.output if args.output else get_basename(inputFilename, "csv")
        convert_pcap_to_csv(inputFilename,outputFilename,args.relative)
    elif args.subparser_name == "csv2sql":
        inputFilename = args.inputPcap
        outputFilename = get_basename(inputFilename, "sqlite")
        convert_pcap_to_sql(inputFilename,outputFilename)
    else:
        parser.print_help()



if __name__ == '__main__':
    main()