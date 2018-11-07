import logging
import pandas as pd
from mptcpanalyzer.connection import MpTcpConnection, TcpConnection
from mptcpanalyzer.data import (load_into_pandas, tcpdest_from_connections, mptcpdest_from_connections,
    load_merged_streams_into_pandas)


log = logging.getLogger(__name__)

@pd.api.extensions.register_dataframe_accessor("tcp")
class TcpAccessor:
    def __init__(self, pandas_obj):
        self._obj = pandas_obj

    def connection(self, streamid):
        return TcpConnection.build_from_dataframe(self._obj, streamid)

def filter_dataframe(
    self,
    rawdf,
    # TODO choose prefix
    merged_one,
    tcpstream=None, 
    mptcpstream=None,
    skipped_subflows=[],
    destinations: list=None,
    extra_query: str=None, **kwargs
):
    """
    Can filter a single dataframe beforehand
    (hence call it several times for several dataframes).

    Feel free to inherit/override this class.

    Args:
        rawdf: Raw dataframe
        kwargs: expanded arguments returned by the parser
        destination: Filters packets depending on their :enum:`.ConnectionRoles`
        stream: keep only the packets related to mptcp.stream == mptcpstream
        skipped_subflows: list of skipped subflows
        extra_query: Add some more filters to the pandas query

    This baseclass can filter on:

    - mptcpstream
    - destination (mptcpstream required)
    - skipped_subflows

    Returns:
        Filtered dataframe
    """
    log.debug("Preprocessing dataframe with extra args %s" % kwargs)
    queries = []
    log.debug("tcp.stream %d mptcp: %d" % (tcpstream, mptcpstream))
    stream = tcpstream if tcpstream is not None else mptcpstream
    dataframe = rawdf

    for skipped_subflow in skipped_subflows:
        log.debug("Skipping subflow %d" % skipped_subflow)
        queries.append(" tcpstream!=%d " % skipped_subflow)

    if stream is not None:
        protocol = "mptcp" if mptcpstream is not None else "tcp"
        log.debug("Filtering %s stream #%d." % (protocol, stream))
        queries.append(protocol + "stream==%d" % stream)


        if protocol == "tcp":
            # generates the "tcpdest" component of the dataframe
            con2 = TcpConnection.build_from_dataframe(dataframe, stream)
            dataframe = tcpdest_from_connections(dataframe, con2)
            # trust plots to do the filtering
            # if destinations is not []:
            #     queries.append(protocol + "dest==%d" % stream)
        else:
            # todo shall do the same for mptcp destinations
            con = MpTcpConnection.build_from_dataframe(dataframe, stream)
            # mptcpdest = main_connection.mptcp_dest_from_tcpdest(tcpdest)
            df = mptcpdest_from_connections(dataframe, con)
            # TODO generate mptcpdest
            # if protocol == "mptcp":
            if destinations is not None:
                raise Exception("destination filtering is not ready yet for mptcp")

                log.debug("Filtering destination")

                # Generate a filter for the connection
                # con = MpTcpConnection.build_from_dataframe(dataframe, stream)
                # q = con.generate_direction_query(destination)
                # queries.append(q)
    if extra_query:
        log.debug("Appending extra_query=%s" % extra_query)
        queries.append(extra_query)

    query = " and ".join(queries)

    # throws when querying with an empty query
    if len(query) > 0:
        log.info("Running query:\n%s\n" % query)
        dataframe.query(query, inplace=True)

    return dataframe

