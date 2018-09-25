from typing import List, Any, Tuple, Dict, Callable
from mptcpanalyzer.connection import MpTcpSubflow, MpTcpConnection, TcpConnection
from mptcpanalyzer import ConnectionRoles
from mptcpanalyzer.data import classify_reinjections
from mptcpanalyzer import _sender, _receiver
import math
import logging

"""
Considerations:
- tcp.analysis.retransmission
- tcp.analysis.lost_segment
- tcp.analysis.fast_retransmission

https://osqa-ask.wireshark.org/questions/16771/tcpanalysisretransmission
"""


def mptcp_compute_throughput(
        rawdf, mptcpstreamid, destination: ConnectionRoles
    # mptcpstreamid2=None
) -> Tuple[bool, Any]:
    """
    Very raw computation: substract highest dsn from lowest by the elapsed time

    Returns:
        a tuple (True/false, dict)
    """

    df = rawdf[rawdf.mptcpstream == mptcpstreamid]
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
        subflow_stats.append({
            'tcpstreamid': tcpstream,
            'bytes': int(subflow_load)
        })

    return True, {
        'mptcpstreamid': mptcpstreamid,
        'mptcp_goodput': total_transferred,
        'mptcp_bytes': sum( map(lambda x: x['bytes'], subflow_stats)),
        'subflow_stats': subflow_stats,
    }



def mptcp_compute_throughput_extended(
    rawdf,  # need the rawdf to classify_reinjections
    stats, # result of mptcp_compute_throughput
    # mptcpstreamid,
    destination : ConnectionRoles, 
    # mptcpstreamid2=None
) -> Tuple[bool, Any]:
    """
    df expects an extended dataframe

    Should display goodput
    """
    df_both = classify_reinjections(rawdf)

    df = df_both[ df_both.mptcpdest == destination ]

    for sf in stats["subflow_stats"]:
        # subflow_stats.append({
        #     'tcpstreamid': tcpstream,
        #     'bytes': subflow_load
        # })
        print("for tcpstream %d" % sf["tcpstreamid"])
        df_stream = df[  _sender("tcpstream") == sf["tcpstreamid"] ]
        
        # TODO eliminate retransmissions too
        # sum( map(lambda x: x['bytes'], subflow_stats)),

        # inexact, we should drop lost packets
        tcp_throughput = df["bytes"].sum()
        mptcp_goodput = df[ df.redundant == False, "bytes"].sum()

        # won
        seq_min = df.tcpseq.min()
        seq_max = df.tcpseq.max()

        tcp_goodput = seq_max - seq_min
        mptcp_goodput = df[ df.redundant == False, "bytes"].sum()
        mptcp_throughput = tcp_throughput

        sf.update({
            # "tcp_througput": tcp_goodput,
            "tcp_goodput": tcp_goodput,

            # cumulative sum of nonredundant dsn packets
            "mptcp_goodput": mptcp_goodput,

            # can be > 1 in case of redundant packets
            "mptcp_throughput_contribution": mptcp_throughput/stats["mptcp_throughput"],

            # 
            "mptcp_goodput_contribution": mptcp_goodput/stats["mptcp_goodput"],
        })

    # for every subflow 
    # for tcpstream, group in df.groupby( _sender("tcpstream")):
    #     print("for tcpstream %d" % tcpstream)
    #     group[ df.redundant == False, "redundant"].sum()

    return  True, stats
