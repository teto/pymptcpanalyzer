from typing import List, Any, Tuple, Dict, Callable
from mptcpanalyzer.connection import MpTcpSubflow, MpTcpConnection, TcpConnection
from mptcpanalyzer import Destination
import math


def mptcp_compute_throughput(rawdf, mptcpstreamid, destination):
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
