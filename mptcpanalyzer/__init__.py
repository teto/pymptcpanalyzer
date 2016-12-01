#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import numpy as np
import pandas as pd
import os
import data
# import tshark
from enum import Enum, IntEnum
from .config import config
from . import cache
from .tshark import TsharkExporter
from mptcpanalyzer.connection import MpTcpConnection, TcpConnection
from collections import namedtuple

log = logging.getLogger(__name__)


"""
fullname: wireshark name
name: shortname used in mptcpanalyzer
type: python type pandas should convert this field to
label: used when plotting
"""
Field = namedtuple('Field', ['fullname', 'name', 'type', 'label', ]) # 'converter'
# Field.__new__.__defaults__ = (None, None)

# cache = # type:
# __config__ = None # type: MpTcpAnalyzerConfig

# """
# The number of rows in the CSV file assigned to metadata (mptcpanalyzer version,
# tshark options etc...)
# """
# METADATA_ROWS = 2


class TcpFlags(Enum):
    NONE = 0
    FIN = 1
    SYN = 2
    RST = 4
    PSH = 8
    ACK = 16
    URG = 32
    ECE = 64
    CWR = 128


def get_fields(field, field2=None):
    """
    Args:
        field: should be a string in Field
        field2: If field2 is None, returns a list with the field asked, else

    Returns:
        a dict( field values: field2 values)
    """

    l = fields_v2()
    keys = map(lambda x: getattr(x, field), l)
    if field2 is None:
        return keys

    return dict(zip(keys, map( lambda x: getattr(x, field2), l)))


class Destination(IntEnum):
    """
    Used to filter datasets and keep packets flowing in only one direction !
    Parser should accept --destination Client --destination Server if you want both.

    TODO: convert back to enum, that was done for bad reasons
    """
    # Client = "client"
    # Server = "server"
    Client = 0
    Server = 1


def reverse_destination(dest: Destination):

    if dest == Destination.Client:
        return Destination.Server
    elif dest == Destination.Server:
        return Destination.Client

    raise Exception()
    # else:
    #     # or assert .
    #     return Destination.Both



class MpTcpException(Exception):
    """
    Exceptions thrown by this module should inherit this in order to let the cli
    filter exceptions
    """
    pass


class MpTcpMissingPcap(MpTcpException):
    pass




def fields_v2():
    """
    It's kinda scary to use float everywhere but when using integers, pandas
    asserts at the first NaN
    It is also not possible to assign "int" for instance to subtype as there may be
    several subtypes in a packet (=> "2,4" which is not recognized as an int)

     Mapping between short names easy to use as a column title (in a CSV file)
     and the wireshark field name
     There are some specific fields that require to use -o instead,
     see tshark -G column-formats

     CAREFUL: when setting the type to int, pandas will throw an error if there
     are still NAs in the column. Relying on float64 permits to overcome this.

    .. note:

        tshark.exe -r file.pcap -T fields -E header=y -e frame.number -e col.AbsTime -e col.DeltaTime -e col.Source -e col.Destination -e col.Protocol -e col.Length -e col.Info

    """
    l = [
        Field("frame.number", "packetid", np.int64, False, ),
        # TODO set tot datetime ?
        Field("frame.time_relative", "reltime", None, False, ),
        # set to deltatime
        Field("frame.time_delta", "time_delta", None, False, ),
        Field("frame.time_epoch", "abstime", None, False, ),
        Field("_ws.col.ipsrc", "ipsrc", str, False, ),
        Field("_ws.col.ipdst", "ipdst", str, False, ),
        Field("ip.src_host", "ipsrc_host", str, False),
        Field("ip.dst_host", "ipdst_host", str, False),
        Field("mptcp.expected_token", "expected_token", str, False),
        # set to categorical ?
        # Field("mptcp.client", "direction", np.float64, False),
        # "mptcp.rawdsn64":        "dsnraw64",
        # "mptcp.ack":        "dack",
        Field("tcp.stream", "tcpstream", np.float64, False),
        Field("mptcp.stream", "mptcpstream", np.float, False),
        Field("tcp.srcport", "sport", np.float, False),
        Field("tcp.dstport", "dport", np.float, False),
        # rawvalue is tcp.window_size_value
        # tcp.window_size takes into account scaling factor !
        Field("tcp.window_size", "rwnd", np.int64, True),
        Field("tcp.options.mptcp.sendkey", "sendkey", np.float64, False),
        Field("tcp.options.mptcp.recvkey", "recvkey", None, False),
        Field("tcp.options.mptcp.recvtok", "recvtok", None, False),
        Field("tcp.options.mptcp.datafin.flag", "datafin", np.float, False),
        Field("tcp.options.mptcp.subtype", "subtype", np.object, False),
        Field("tcp.flags", "tcpflags", np.float64, False),
        Field("tcp.options.mptcp.rawdataseqno", "dss_dsn", np.float64, "DSS Sequence Number"),
        Field("tcp.options.mptcp.rawdataack", "dss_rawack", np.float64, "DSS raw ack"),
        Field("tcp.options.mptcp.subflowseqno", "dss_ssn", np.float64, "DSS Subflow Sequence Number"),
        Field("tcp.options.mptcp.datalvllen", "dss_length", np.float64, "DSS length"),
        Field("tcp.options.mptcp.addrid", "addrid", None, False),
        Field("mptcp.master", "master", bool, False),
        Field("tcp.seq", "tcpseq", np.float64, "TCP sequence number"),
        Field("tcp.len", "tcplen", np.float64, "TCP segment length"),
        Field("mptcp.rawdsn64", "dsnraw64", np.float64, "Raw Data Sequence Number"),
        Field("mptcp.ack", "dack", np.float64, "MPTCP relative Ack"),
        Field("mptcp.dsn", "dsn", np.float64, "Data Sequence Number"),
        Field("mptcp.related_mapping", "related_mappings", None, "DSS"),
        Field("mptcp.duplicated_dsn", "reinjections", None, "Reinjections"),
    ]
    return l


# TODO move to an io package ?
def load_into_pandas(
    input_file: str,
    regen: bool=False,
    # metadata: Metadata=Metadata(), # passer une fct plutot qui check validite ?
) -> pd.DataFrame:
    """
    load csv mptpcp data into pandas

    Args:
        regen: Ignore the cache and regenerate any cached csv file from
        the input pcap
    """
    log.debug("Asked to load %s" % input_file)

    filename = os.path.expanduser(input_file)
    filename = os.path.realpath(filename)
    # todo addd csv extension if needed
    cfg = config["mptcpanalyzer"]

    # csv_filename = self.get_matching_csv_filename(filename, regen)
    is_cache_valid = cache.cache.is_cache_valid(filename, )
    # if os.path.isfile(cachename):
    csv_filename = cache.cache.cacheuid(filename)

    log.debug("valid cache: %d cachename: %s" % (is_cache_valid, csv_filename))
    if regen or not is_cache_valid:
        log.info("Cache invalid... Converting %s into %s" % (filename, csv_filename))

        exporter = TsharkExporter(
            cfg["tshark_binary"],
            cfg["delimiter"],
            cfg["wireshark_profile"],
        )

        retcode, stderr = exporter.export_to_csv(
            filename,
            csv_filename,
            get_fields("fullname", "name"),
            tshark_filter="mptcp and not icmp"
        )
        log.info("exporter exited with code=%d", retcode)
        if retcode != 0:
            # remove invalid cache log.exception
            os.remove(csv_filename)
            raise Exception(stderr)


    temp = get_fields("fullname", "type")
    dtypes = {k: v for k, v in temp.items() if v is not None}
    log.debug("Loading a csv file %s" % csv_filename)

    with open(csv_filename) as fd:
        # first line is metadata
        # TODO: creer classe metadata read/write ?
        # metadata = fd.readline()

        data = pd.read_csv(
            fd,
            # skip_blank_lines=True,
            # hum not needed with comment='#'
            comment='#',
            # we don't need 'header' when metadata is with comment
            # header=mp.METADATA_ROWS, # read column names from row 2 (before, it's metadata)
            # skiprows
            sep=cfg["delimiter"],
            dtype=dtypes,
            converters={
                "tcp.flags": lambda x: int(x, 16),
                # reinjections, converts to list of integers
                "mptcp.duplicated_dsn": lambda x: list(map(int, x.split(','))) if x else np.nan,
                #"mptcp.related_mapping": lambda x: x.split(','),
            },
            # memory_map=True, # could speed up processing
        )
        # TODO:
        # No columns to parse from file
        data.rename(inplace=True, columns=get_fields("fullname", "name"))
        log.debug("Column names: %s", data.columns)

    # pp = pprint.PrettyPrinter(indent=4)
    # log.debug("Dtypes after load:%s\n" % pp.pformat(data.dtypes))
    return data


# on a pas le filename :s
def pandas_to_csv(df: pd.DataFrame, filename, **kwargs):
    return df.to_csv(
        filename, # output
        # columns=self.columns,
        # how do we get the config
        sep=config["mptcpanalyzer"]["delimiter"],
        # index=True, # hide Index
        header=True, # add
        **kwargs
    )


def merge_tcp_dataframes(df1: pd.DataFrame, df2: pd.DataFrame, tcpstream: int):
    """
    """
    h1_df, h2_df = df1, df2
    cfg = config
    main_connection = TcpConnection.build_from_dataframe(h1_df, tcpstream)

    # du coup on a une liste
    mappings = data.map_tcp_stream(h2_df, main_connection)

    print("Found mappings %s" % mappings)
    if len(mappings) <= 0:
        print("Could not find a match in the second pcap for tcpstream %d" % tcpstream)
        return


    # limit number of packets while testing
    # HACK to process faster
    h1_df = debug_convert(h1_df)
    h2_df = debug_convert(h2_df)

    print("len(df1)=", len(h1_df), " len(rawdf2)=", len(h2_df))
    mapped_connection, score = mappings[0]
    print("Found mappings %s" % mappings)
    for con, score in mappings:
        print("Con: %s" % (con))

    # print(h1_df["abstime"].head())
    # print(h1_df.head())
    # # should be sorted, to be sure we could use min() but more costly
    # min_h1 = h1_df.loc[0,'abstime']
    # min_h2 = h2_df.loc[0,'abstime']
    # # min
    # if min_h1 < min_h2:
    #     print("Looks like h1 is the sender")
    #     client_df = h1_df
    #     receiver_df = h2_df
    # else:
    #     print("Looks like h2 is the sender")
    #     client_df = h2_df
    #     receiver_df = h1_df

    print("Mapped connection %s to %s" % (mapped_connection, main_connection))

    #  mapped_connection should be of type TcpConnection
    # global __config__
    # TODO we clean accordingly
    # TODO for both directions
    # total_results
    total = None # pd.DataFrame()
    for dest in Destination:
        q = main_connection.generate_direction_query(dest)
        h1_unidirectional_df = h1_df.query(q)
        q = mapped_connection.generate_direction_query(dest)
        h2_unidirectional_df = h2_df.query(q)


        # if dest == mp.Destination.Client:
        #     local_sender_df, local_receiver_df = local_receiver_df, local_sender_df
        res = self.generate_tcp_directional_owd_df(h1_unidirectional_df, h2_unidirectional_df, dest)
        res['dest'] = dest.name
        total = pd.concat([res, total])

        # TODO remove in the future
        filename = "merge_%d_%s.csv" % (mptcpstream, dest)
        res.to_csv(
            filename, # output
            columns=self.columns,
            # how do we get the config
            sep=cfg["mptcpanalyzer"]["delimiter"],
            # index=True, # hide Index
            header=True, # add
            # sep=main.config["DEFAULT"]["delimiter"],
        )
    print("Delimiter:", sep=cfg["mptcpanalyzer"]["delimiter"])

    # filename = "merge_%d_%d.csv" % (tcpstreamid_host0, tcpstreamid_host1)
    # TODO reorder columns to have packet ids first !
    firstcols = ['packetid_h1', 'packetid_h2', 'dest', 'owd']
    total = total.reindex(columns=firstcols + list(filter(lambda x: x not in firstcols, total.columns.tolist())))
    total.to_csv(
        cachename, # output
        # columns=self.columns,
        index=False,
        header=True,
        # sep=main.config["DEFAULT"]["delimiter"],
    )
    return total

def merge_mptcp_dataframes(df1, df2, ):
    pass

# TODO remove ?
# def filter_df(skip_subflows=None, **kwargs):
#         """
#         Filters a pandas DataFrame

#         Args:
#             data: a Pandas dataset
#             kwargs: Accepted keywords are

#         direction = client or server
#         """
#         # query = gen_ip_filter(**kwargs)
#         dat = data
#         for field, value in dict(**kwargs).items():
#             print("name, value", field)
#             query = "{field} == '{value}'".format(field=field, value=value)

    # direction = kwargs.get("direction")
    # if direction:
    #     # dat = data[(data.mptcpstream == args.mptcpstream) & (data.direction == args.direction)]
    #     # dat = main[data.mptcpstream == args.mptcpstream]
    #     query = "direction == %d" % mp.flow_directions[direction]
        # log.debug("Running query %s" % query)
        # dat = data.query(query)
    # return dat
