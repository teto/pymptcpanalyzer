#!/usr/bin/env python
# -*- coding: utf-8 -*-
# from pkgutil import extend_path

import logging
import numpy as np
from enum import Enum

from collections import namedtuple

# h = logging.FileHandler(".mptcpanalyzer-" + str(os.getpid()), delay=True)
# TODO let final script set the handler

logger = logging.getLogger(__name__)

Field = namedtuple('Field', ['fullname', 'name', 'type', 'label', ]) # 'converter'

Field.__new__.__defaults__ = (None, None)


def get_fields (field, field2=None):
    """
    :param field: should be a string in Field
    :param field2: If field2 is None, returns a list with the field asked, else 
    returns a dict( field values: field2 values)
    """

    l = fields_v2()
    keys = map(lambda x: getattr(x, field), l)
    if field2 is None:
        return keys

    return dict(zip(keys, map( lambda x: getattr(x, field2), l)))


class Destination(Enum):
    """
    Used to filter dataset
    """
    Client = "client"
    Server = "server"
    Both = "Both"

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

    tshark.exe -r file.pcap -T fields -E header=y -e frame.number -e col.AbsTime -e col.DeltaTime -e col.Source -e col.Destination -e col.Protocol -e col.Length -e col.Info

    TODO use converters for datetime
    """
    l = [
        Field("frame.number", "packetid", np.int64, False),
        # TODO set tot datetime ?
        Field("frame.time_relative", "reltime", None, False,),
        # set to deltatime
        Field("frame.time_delta", "time_delta", None, False),
        Field("frame.time_epoch", "abstime", None, False),
        Field("_ws.col.ipsrc", "ipsrc", str, False),
        Field("_ws.col.ipdst", "ipdst", str, False),
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
    ]
    return l


def filter_df(skip_subflows=None, **kwargs):
        """
        Filters a pandas DataFrame
        :param data a Pandas dataset
        :param kwargs Accepted keywords are

        direction = client or server
        """
        # query = gen_ip_filter(**kwargs)
        dat = data
        for field, value in dict(**kwargs).items():
            print("name, value", field)
            query = "{field} == '{value}'".format(field=field, value=value)

        # direction = kwargs.get("direction")
        # if direction:
        #     # dat = data[(data.mptcpstream == args.mptcpstream) & (data.direction == args.direction)]
        #     # dat = main[data.mptcpstream == args.mptcpstream]
        #     query = "direction == %d" % mp.flow_directions[direction]

            log.debug("Running query %s" % query)
            dat = data.query(query)
        return dat

