#!/usr/bin/env python
# -*- coding: utf-8 -*-
import logging
import os
import pandas as pd
from mptcpanalyzer.tshark import TsharkExporter, Filetype
from mptcpanalyzer.config import MpTcpAnalyzerConfig
from mptcpanalyzer.connection import MpTcpSubflow, MpTcpConnection
from typing import List

log = logging.getLogger(__name__)



def build_connections_from_dataset(df: pd.DataFrame, mptcpstreams: List[int]) -> List[MpTcpConnection]:
    """
    """
    connections
    for mptcpstream, df in df1:
        if mptcpstream not in idx:
            continue


def compare_filtered_df(df1, df2) -> int :
    """
    ALREADY FILTERED dataframes

    Returns:
        a score
    """

    score = 0
    main = MpTcpConnection.build_from_dataframe(df1, mptcpstream)
    other = MpTcpConnection.build_from_dataframe(df2, mptcpstream)

    # tcpstreams1 = ds1.groupby('tcpstream')
    # tcpstreams2 = ds2.groupby('tcpstream')
    # log.debug ("ds1 has %d subflow(s)." % (len(tcpstreams1)))
    # log.debug ("ds2 has %d subflow(s)." % (len(tcpstreams2)))
    if len (main.subflows) != len(other.subflows):
        log.debug("FISHY: Datasets contain a different number of subflows (d vs d)" % ())
        score -= 5


    common_sf = []
    for sf in main.subflows:
        if sf in other.subflows or sf.reversed in other.subflows:
            log.debug("Subflow %s in common" % sf)
            score += 10
            common_sf.append(sf)

    # TODO compare start times supposing cloak are insync ?
    return score

    # To filter the dataset, you can refer to 
    # mappings = []
    # for tcpstream1, gr2 in tcpstreams1:
    #     # for tcpstream2, gr2 in tcpstreams2:
    #     # look for similar packets in ds2
    #     print ("=== toto")

    #     # result = ds2[ (ds2.ipsrc == gr2['ipdst'].iloc[0])
    #          # & (ds2.ipdst == gr2['ipsrc'].iloc[0])
    #          # & (ds2.sport == gr2['dport'].iloc[0])
    #          # & (ds2.dport == gr2['sport'].iloc[0])
    #          # ]
    #     # should be ok
    #     # sf = MpTcpSubflow ( gr2['ipsrc'].iloc[0], gr2['ipdst'].iloc[0],
    #     #         gr2['sport'].iloc[0], gr2['dport'].iloc[0])

    #     # print("Sf=" , sf)
    #     # result = ds2[ (ds2.ipsrc == sf.ipsrc)
    #     #      & (ds2.ipdst == sf.ipdst)
    #     #      & (ds2.sport == sf.sport)
    #     #      & (ds2.dport == sf.dport)
    #     #      ]

        # if len(result):
        #     # print ("=== zozo")
        #     entry = tuple([tcpstream1, result['tcpstream'].iloc[0], sf])
        #     # print("Found a mapping %r" % entry) 
        #     mappings.append(entry)

        #     print("match for stream %s" % tcpstream1)
        # else:
        #     print("No match for stream %s" % tcpstream1)

            # TODO use a print function ?
            # line = "\ttcp.stream {tcpstream} : {srcip}:{sport} <-> {dstip}:{dport}".format(
            #     tcpstream=tcpstream1,
            #     srcip=gr2['ipsrc'].iloc[0],
            #     sport=gr2['sport'].iloc[0], 
            #     dstip=gr2['ipdst'].iloc[0], 
            #     dport=gr2['dport'].iloc[0]
            #     )
            # print(line)

def map_subflows_between_2_datasets(rawdf1 : pd.DataFrame, rawdf2: pd.DataFrame, idx: List[int]=None) -> List:
    """
    .. warn: Do not trust the results yet WIP !

    This function tries to map a mptcp.stream from a dataframe (aka pcap) to mptcp.stream
    in another dataframe.

    It goes over 

    Todo:
        - Every stream should be mapped to only one other (add a check for that ?)


    Args:
        ds1, ds2
        streams : List of mptcpstream chosen from rawds1, for which we want the equivalent id in rawdf2

    Returns:
        a List of tuples (Connection1, Connection2)

    """
    log.warn("mapping between datasets is not considered trustable yet")
    results = [] # :type List[tuples]
    # if idx
    #    filtereddf1. 
    df1 = rawdf1.groupby("mptcpstream")
    # ds2 = rawdf2.groupby("mptcpstream")


    mappings=[]
    # scores = 
    for mptcpstream, df in df1:
        if idx and mptcpstream not in idx:
            continue

        # main = MpTcpConnection.build_from_dataframe(df, mptcpstream)
        score = -1
        results = []

        for mptcpstream, df2 in rawdf2.groupby("mptcpstream"):
            # other = MpTcpConnection.build_from_dataframe(df2, mptcpstream)
            # other = 
            score = compare_filtered_df(df1, df2)
            results.append((mptcpstream, score))
            
        # sort based on the score
        results.sort(key=lambda x: x[1])
        mappings.append( (main, results[-1] if len(results) else None))

    return mappings


