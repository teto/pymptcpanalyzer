#!/usr/bin/env python
# -*- coding: utf-8 -*-
import logging
import os
from mptcpanalyzer.tshark import TsharkExporter, Filetype
from mptcpanalyzer.config import MpTcpAnalyzerConfig
from mptcpanalyzer import MpTcpSubflow

log = logging.getLogger(__name__)


def map_subflows_between_2_datasets(ds1,ds2):
    """
    TODO maybe pass an iterable with tuple of mptcpstreams ?
        ds1 = ds1[(ds1.mptcpstream == args.mptcp_client_id)]        
        ds2 = ds2[ds2.mptcpstream == args.mptcp_server_id]

    Takes 2 datasets ALREADY FILTERED and returns 
    # a dictiorary mapping
    -> a list of tuples
    ds1 TCP flows to ds2 TCP flows
    """
    
    tcpstreams1 = ds1.groupby('tcpstream')
    tcpstreams2 = ds2.groupby('tcpstream')
    log.debug ("ds1 has %d subflow(s)." % (len(tcpstreams1)))
    log.debug ("ds2 has %d subflow(s)." % (len(tcpstreams2)))
    if len (tcpstreams1) != len(tcpstreams2):
        log.warn("FISHY: Datasets contain a different number of subflows")

    # To filter the dataset, you can refer to 
    mappings = []
    for tcpstream1, gr2 in tcpstreams1:
        # for tcpstream2, gr2 in tcpstreams2:
        # look for similar packets in ds2
        print ("=== toto")

        # result = ds2[ (ds2.ipsrc == gr2['ipdst'].iloc[0])
             # & (ds2.ipdst == gr2['ipsrc'].iloc[0])
             # & (ds2.sport == gr2['dport'].iloc[0])
             # & (ds2.dport == gr2['sport'].iloc[0])
             # ]
        # should be ok
        sf = MpTcpSubflow ( gr2['ipsrc'].iloc[0], gr2['ipdst'].iloc[0],
                gr2['sport'].iloc[0], gr2['dport'].iloc[0])

        print("Sf=" , sf)
        result = ds2[ (ds2.ipsrc == sf.ipsrc)
             & (ds2.ipdst == sf.ipdst)
             & (ds2.sport == sf.sport)
             & (ds2.dport == sf.dport)
             ]

        if len(result):
            # print ("=== zozo")
            entry = tuple([tcpstream1, result['tcpstream'].iloc[0], sf])
            # print("Found a mapping %r" % entry) 
            mappings.append(entry)

            print("match for stream %s" % tcpstream1)
        else:
            print("No match for stream %s" % tcpstream1)

            # TODO use a print function ?
            # line = "\ttcp.stream {tcpstream} : {srcip}:{sport} <-> {dstip}:{dport}".format(
            #     tcpstream=tcpstream1,
            #     srcip=gr2['ipsrc'].iloc[0],
            #     sport=gr2['sport'].iloc[0], 
            #     dstip=gr2['ipdst'].iloc[0], 
            #     dport=gr2['dport'].iloc[0]
            #     )
            # print(line)
    return mappings


