from typing import List, Any, Tuple, Dict, Callable
from mptcpanalyzer.connection import MpTcpSubflow, MpTcpConnection, TcpConnection
from mptcpanalyzer import ConnectionRoles
from mptcpanalyzer.data import classify_reinjections
from mptcpanalyzer import _sender, _receiver
import math
import logging


def mptcp_compute_throughput(
        rawdf, mptcpstreamid, destination: ConnectionRoles
    # mptcpstreamid2=None
) -> Tuple[bool, Any]:
    """
    Very raw computation: substract highest dsn from lowest by the elapsed time

    Returns:
        a tuple (True/false, dict)
    """

    df = rawdf[ rawdf.mptcpstream == mptcpstreamid]
    if df.empty:
        return False, "No packet with mptcp.stream == %d" % mptcpstreamid

    con = MpTcpConnection.build_from_dataframe(df, mptcpstreamid)
    q = con.generate_direction_query(destination)
    df = unidirectional_df = df.query(q)

    dsn_min = df.dss_dsn.min()
    dsn_max = df.dss_dsn.max()
    total_transferred = dsn_max - dsn_min
    d = df.groupby('tcpstream')
    subflow_stats : List[Any] = []
    for tcpstream, group in d:
        # TODO drop retransmitted
        subflow_load = group.drop_duplicates(subset="dss_dsn").dss_length.sum()
        subflow_load = subflow_load if not math.isnan(subflow_load) else 0
        print('subflow_load', subflow_load)
        subflow_stats.append({
            'tcpstreamid': tcpstream,
            'bytes': subflow_load
        })

    return True, {
        'mptcpstreamid': mptcpstreamid,
        'total_goodput': total_transferred,
        'total_bytes': sum( map(lambda x: x['bytes'], subflow_stats)),
        'subflow_stats': subflow_stats,
    }


def mptcp_compute_throughput_extended(
    rawdf, 
    stats, # result of mptcp_compute_throughput
    # mptcpstreamid,
    destination : ConnectionRoles, 
    # mptcpstreamid2=None
) -> Tuple[bool, str]:
    """
    df expects an extended dataframe

    Should display goodput
    """
    df_both = classify_reinjections(rawdf)

    df = df_both[ df_both.mptcpdest == destination ]

    # df.sum 

    for sf in stats["subflow_stats"]:
        # subflow_stats.append({
        #     'tcpstreamid': tcpstream,
        #     'bytes': subflow_load
        # })
        print("for tcpstream %d" % sf["tcpstreamid"])
        df_stream = df[  _sender("tcpstream") == sf["tcpstreamid"] ]
        
        effective = [ df.redundant == False, "redundant"].sum()
        sf.update( {
            "goodput": effective
            "effective_ratio": effective
            "ratio": 
            })

    # for every subflow 
    # for tcpstream, group in df.groupby( _sender("tcpstream")):
    #     print("for tcpstream %d" % tcpstream)
    #     group[ df.redundant == False, "redundant"].sum()

    return  True, {}
