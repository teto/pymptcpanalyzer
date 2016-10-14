#!/usr/bin/env python
# -*- coding: utf-8 -*-
import logging
import os
import pandas as pd
import numpy as np
from mptcpanalyzer.tshark import TsharkExporter, Filetype
from mptcpanalyzer.config import MpTcpAnalyzerConfig
from mptcpanalyzer.connection import MpTcpSubflow, MpTcpConnection, TcpConnection
from typing import List, Any, Tuple
import math

log = logging.getLogger(__name__)

def ignore(f1, f2):
    return 0

def exact(f1, f2):
    return float('-inf') if f1 != f2 else 10

"""
invariant: True if not modified by the network
Of the form Field.shortname

Have a look at the graphic slide 28:
https://www-phare.lip6.fr/cloudnet12/Multipath-TCP-tutorial-cloudnet.pptx
"""
scoring_rules = {
        "packetid": ignore,
        "abstime": ignore,
        "default_time": ignore,
        "expected_token": exact,
        "sport": exact,
        "dport": exact,
        "rwnd": exact,
        "sendkey": exact,
        "rcvkey": exact,
        "rcvtoken": exact,
        "tcpflags": exact,
        "dss_dsn": exact,
        "dss_rawack": exact,
        "dss_ssn": exact,
        "tcpseq": exact,
        "tcplen": exact,
        # "dsnraw64": exact,

}

# def build_connections_from_dataset(df: pd.DataFrame, mptcpstreams: List[int]) -> List[MpTcpConnection]:
#     """
#     """
#     connections
#     for mptcpstream, df in df1:
#         if mptcpstream not in idx:
#             continue



def map_tcp_packet(df, packet) -> List[Tuple[Any, float]]: # Tuple(row, score)
    # instead should be index ?
    """
    Packets may disappear, get retransmitted

    Args:
        packet:

    Returns:
        a list of tuples (index, score)
    """

    def _cmp_packets(p1, p2) -> float:
        """
        returns a score
        """
        log.debug("comparing packets %s and %s" % (p1, p2))
        score = 0
        # crude approach, packet with most common fields is declared the best
        log.debug("compareason based on columns %s " % df.columns)
        for field in df.columns:
            try:
                f1 = getattr(p1, field)
                f2 = getattr(p2, field)
                score += scoring_rules[field](f1, f2)
                log.debug("new score after column [%s] = %f" % (field, score))
                if math.isinf(score):
                    break
            except Exception as e:
                log.debug(e)

        # if p1.tcpflags != p2.tcpflags:
        #     score -= 10
        # if p1.dsn != p2.dsn:
        #     score -= abs(p2.dsn - p1.dsn)
        # if p1.dack != p2.dack:
        #     score -= abs(p2.dack - p1.dack)
        # when several packets have same dsn/ack number, we add the difference between 
        # absolute times so that the first gets a better score to referee between those
        # score -= abs(p2.abstime - p1.abstime)
        return score

    scores = [] # type: List[Any]

    for row in df.itertuples():
        score = _cmp_packets(packet, row)

        # we don't append inf results for performance reasons
        if not math.isinf(score):
            scores.append((row.Index, score))

    # sort by score
    scores.sort(key=lambda x: x[1], reverse=True)
    return scores


def map_tcp_packets(rawdf1, rawdf2, con1: TcpConnection, con2: TcpConnection) -> pd.DataFrame:
    """
    Stream ids must already mapped 

    algo:
        Computes a score on a per packet basis
        Based 

    Returns:
        a dataframe with 
    """
    df1 = rawdf1[rawdf1["tcpstream"] == con1.tcpstreamid]
    df2 = rawdf2[rawdf2["tcpstream"] == con2.tcpstreamid]
    # DataFrame.add(other, axis='columns', level=None, fill_value=None)
    # adds a new column that contains only nan
    log.debug("Mapping TCP packets between TODO")
    df1.set_index('packetid', inplace=True)
    df2.set_index('packetid', inplace=True)

    # returns a new df with new columns
    df_final = df1.assign(mapped_index=np.nan, score=np.nan)

    # # Problem is to identify lost packets and retransmitted ones 
    # # so that they map to the same or none ?
    limit = 5
    for row in df_final.itertuples():
        print(len(df2))
        scores = map_tcp_packet(df2, row)
        print("first %d packets (pandas.index/score)s=\n%s" % (limit, scores[:limit]))
        # takes best score index
        # print("row=", df_final.loc[row.index, "packetid"])
        # df_final.loc[row.index , 'mapped_index'] = 2 # scores[0][0]
        # print(type(row.Index), type(row.index))
        if len(scores) >= 1:
            idx, score = scores[0]
            df_final.set_value(row.Index, 'mapped_index', idx)
            df_final.set_value(row.Index, 'score', score)

        # drop the chosen index so that it doesn't get used a second time
        # todo pb la c qu'on utilise les packet id comme des index :/
            print("Score %f assigned to index %s" % (score, idx))
            # print(df2)
            # df2.drop(df2.index[[idx]], inplace=True)
            df2.drop(idx, inplace=True)
        else:
            log.debug("No map found for this packet")

        # print("registered = %s" % ( df_final.loc[row.Index, 'mapped_index'])) # , ' at index: ', row.index ) 

    print("head=\n", df_final.head())
    return df_final


# def compare_filtered_df(df1, mptcpstream1, df2, mptcpstream2) -> int :
def compare_filtered_df(df1, main: MpTcpConnection, df2, other: MpTcpConnection) -> float:
    """
    ALREADY FILTERED dataframes

    Returns:
        a score
        - '-inf' means it's not possible those 2 matched
        - '+inf' means 
    """

    score = 0
    # mptcpstream = df1[df1.mptcpstream]
    # print("df1=%r"% df1)
    # print("stream=", df1.indices) #, 'mptcpstream']
    # # df1.as_index
    # print("rows", df1.nth(0).index )
    # print("keys", df1.keys )
    # print("keys", df1.group_keys)
    # print(dir(df1))
    # main = MpTcpConnection.build_from_dataframe(df1, mptcpstream1)
    # other = MpTcpConnection.build_from_dataframe(df2, mptcpstream2)

    # tcpstreams1 = ds1.groupby('tcpstream')
    # tcpstreams2 = ds2.groupby('tcpstream')
    # log.debug ("ds1 has %d subflow(s)." % (len(tcpstreams1)))
    # log.debug ("ds2 has %d subflow(s)." % (len(tcpstreams2)))
    if len(main.subflows) != len(other.subflows):
        log.debug("FISHY: Datasets contain a different number of subflows (d vs d)" % ())
        score -= 5

    common_sf = []

    if main.server_key == other.server_key and main.client_key == other.client_key:
        log.debug("matching keys => same")
        return float('inf')


    # TODO check there is at least the master
    # with nat, ips don't mean a thing ?
    for sf in main.subflows:
        # TODO compute a score
        if sf in other.subflows or sf.reversed in other.subflows:
            log.debug("Subflow %s in common" % sf)
            score += 10
            common_sf.append(sf)
        else:
            log.debug("subflows don't match")
        # elif sf.master:
        #     return float('-inf')

    # TODO compare start times supposing cloak are insync ?
    return score


# TODO rename
def mptcp_match_connections(rawdf1: pd.DataFrame, rawdf2: pd.DataFrame, idx: List[int]=None):


    mappings = {}
    for mptcpstream1 in rawdf1["mptcpstream"].unique():
        if idx and mptcpstream1 not in idx:
            continue

        main = MpTcpConnection.build_from_dataframe(rawdf1, mptcpstream1)
        results = mptcp_match_connection(rawdf1, rawdf2, main)
        mappings.update({main: results})
    return mappings


# def mptcp_match_connection(rawdf1 : pd.DataFrame, rawdf2: pd.DataFrame, idx: List[int]=None):
def mptcp_match_connection(rawdf1: pd.DataFrame, rawdf2: pd.DataFrame, main: MpTcpConnection):
    """
    .. warn: Do not trust the results yet WIP !

    This function tries to map a mptcp.stream from a dataframe (aka pcap) to mptcp.stream
    in another dataframe.

    It goes over 

    Todo:
        - Every stream should be mapped to only one other (add a check for that ?)


    Args:
        ds1, ds2
        idx : List of mptcpstream chosen from rawds1, for which we want the equivalent id in rawdf2

    Returns:
        a dict {Connection1: [(Connection2, score)])

    """
    log.warning("mapping between datasets is not considered trustable yet")
    results = [] # type: List[Tuple[Any, float]]
    # if idx
    #    filtereddf1. 
    # df1 = rawdf1.groupby("mptcpstream")
    # ds2 = rawdf2.groupby("mptcpstream")


    mappings = {} # type: Dict[int,Tuple[Any, float]]
    # scores = 
    # df['id'],unique()

    # main = MpTcpConnection.build_from_dataframe(df, mptcpstream)
    score = -1 # type: float
    results = []

    for mptcpstream2 in rawdf2["mptcpstream"].unique():
        other = MpTcpConnection.build_from_dataframe(rawdf2, mptcpstream2)
        score = compare_filtered_df(rawdf1, main, rawdf2, other)
        if score > float('-inf'):
            results.append((other, score))

    # sort based on the score
    results.sort(key=lambda x: x[1])

    return results
