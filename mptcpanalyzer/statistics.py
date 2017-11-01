#!/usr/bin/env python
# -*- coding: utf-8 -*-
from typing import List, Any, Tuple, Dict, Callable


def compute_throughput(rawdf, mptcpstreamid):
    """
    TODO thath should be per destination

    Returns a tuple (True/false, dict)
    """
    df = rawdf[rawdf.mptcpstream == mptcpstreamid]
    if df.empty:
        return False, "No packet with mptcp.stream == %d" % mptcpstreamid

    # for instance
    dsn_min = df.dss_dsn.min()
    dsn_max = df.dss_dsn.max()
    total_transferred = dsn_max - dsn_min
    d = df.groupby('tcpstream')
    # drop_duplicates(subset='rownum', take_last=True)
    subflow_stats : List[Any] = []
    for tcpstream, group in d:
        # todo use tcp_seq_max/ tcp_seq_min
        # drop retransmitted
        subflow_load = group.drop_duplicates(subset="dss_dsn").dss_length.sum()
        print('subflow_load', subflow_load)
        subflow_stats.append({'tcpstreamid': tcpstream, 'bytes': subflow_load})
        # print(subflow_load)
        # print('tcpstream %d transferred %d out of %d, hence is responsible for %f%%' % (tcpstream, subflow_load, total_transferred, subflow_load / total_transferred * 100))

    return True, {
        'mptcpstreamid': mptcpstreamid,
        'total_goodput': total_transferred,
        'total_bytes': sum( map(lambda x: x['bytes'], subflow_stats)),
        'subflow_stats': subflow_stats,
    }
