import pandas as pd
import logging
from mptcpanalyzer import ConnectionRoles, MpTcpException

from typing import List, NamedTuple, Tuple, Dict
from enum import Enum

log = logging.getLogger(__name__)


def swap_role(role : ConnectionRoles):
    """while waiting to get next to work with enum"""
    if role == ConnectionRoles.Server:
        return ConnectionRoles.Client
    else:
        return ConnectionRoles.Server


class Filetype(Enum):
    unsupported = 0
    pcap = 1
    sql = 2
    csv = 3

class TcpConnection:
    """
    Everything capable of identifying a connection

    Note:
        There exists in ipaddress module

    Attributes:
        tcpstreamid: wireshark tcp.stream
    """
    def __init__(
        self,
        tcpstreamid: int,
        tcpclientip, tcpserverip,
        client_port: int, server_port: int,
        **kwargs
    ) -> None:
        self.tcpstreamid = tcpstreamid 
        self.tcpclient_ip = tcpclientip
        self.tcpserver_ip = tcpserverip
        self.server_port = server_port
        self.client_port = client_port
        self.isn = kwargs.get('isn')


    def generate_direction_query(self, tcpdest: ConnectionRoles) -> str:
        """
        Filter packets according to the tcp notion of client/server destination
        """
        q = "tcpstream==%d " % self.tcpstreamid
        if tcpdest is None:
            return q

        if tcpdest == ConnectionRoles.Client:
            ipsrc = self.tcpserver_ip
            server_port = self.server_port
        else:
            ipsrc = self.tcpclient_ip
            server_port = self.client_port

        # server_port used to be
        q += " and ipsrc=='%s' and sport==%d " % (ipsrc, server_port)
        return q

    def sort_candidates(self, ):
        """
        Sort a list 
        """
        pass

    def format_mapping(self, mapping: 'TcpMapping', verbose=False):
        # res = "tcp stream {c1.tcpstreamid} <-> {c2.tcpstreamid} with score={score}".format(
        res = "{c1} mapped to {c2} with score={score}".format(
                c1=self, c2=mapping[0], score=mapping[1])

        # print(res)
        return res

    def score(self, other):
        """
        If every parameter is equal, returns +oo else 0
        TODO also match on isn in case ports got reused
        """
        score = 0
        if (self.tcpserver_ip == other.tcpserver_ip and
                self.tcpclient_ip == other.tcpclient_ip and
                self.client_port == other.client_port and
                self.server_port == other.server_port):
                return float('inf')

        score += 10  if self.tcpserver_ip == other.tcpserver_ip else 0
        score += 10  if self.tcpclient_ip == other.tcpclient_ip else 0
        score += 10  if self.client_port == other.client_port else 0
        score += 10  if self.server_port == other.server_port else 0

        # TODO more granular score
        return score

    def __eq__(self, other):
        """
        Ignores
        A NAT/PAT could have rewritten IPs in which case you probably
        should add another function like score
        """
        # print("self=%r"% self)
        # print("other=%r"% other)
        return self.score(other) == float('inf')

    @staticmethod
    def build_from_dataframe(rawdf: pd.DataFrame, tcpstreamid: int) -> 'TcpConnection':
        """
        Instantiates a class that describes an MPTCP connection
        """

        def get_index_of_non_null_values(serie):
            # http://stackoverflow.com/questions/14016247/python-find-integer-index-of-rows-with-nan-in-pandas/14033137#14033137
            # pd.np.nan == pd.np.nan retursn false in panda so one should use notnull(), isnull()
            return serie.notnull().nonzero()[0]


        df = rawdf[rawdf.tcpstream == tcpstreamid]
        if len(df.index) == 0:
            # print(rawdf.head())
            raise MpTcpException("No packet with this tcp.stream id %r" % tcpstreamid)

        # + mp.TcpFlags TODO record ISN !!
        # syns = df[df.tcpflags == mp.TcpFlags.SYN]
        # if len(syns) == 0
        #     raise MpTcpException("No packet with this stream id")

        row = df.iloc[0,]
        result = TcpConnection(
            tcpstreamid,
            row['ipsrc'], row['ipdst'],
            client_port=row['sport'], server_port=row['dport']
        )
        log.debug("Created connection %s", result)
        return result

    def reversed(self):
        # doesn't make sense really ?
        return TcpConnection(
            self.tcpstreamid, self.tcpserver_ip, self.tcpclient_ip,
            self.server_port, self.client_port,
        )

    def __repr__(self):
        return self.__str__()

    def __str__(self):
        # :>5d
        # TODO should be converted to int instead, would spare some memory
        line = ("tcp.stream {s.tcpstreamid:.0f}: {s.tcpclient_ip}:{s.client_port:0>5.0f} "
                " <-> {s.tcpserver_ip}:{s.server_port:0>5.0f} ").format(s=self,
                        # tcpstreamid=self.tcpstreamid
                        )
        return line


class MpTcpSubflow(TcpConnection):
    """

    """

    def __init__(self, mptcpdest: ConnectionRoles, addrid=None, **kwargs) -> None:
        super().__init__(**kwargs)
        self.addrid = addrid
        # self.rcv_token = rcv_token
        # token_owner ?
        """ to which mptcp side belongs the tcp server"""
        self.mptcpdest = mptcpdest

    @staticmethod
    def create_subflow(**kwargs):
        """
        Args:
        """
        sf = MpTcpSubflow(**kwargs)
        return sf

    def reversed(self):
        res = self.create_subflow(
            mptcpdest=swap_role(self.mptcpdest),
            tcpstreamid=self.tcpstreamid, 
            tcpclientip=self.tcpserver_ip, 
            tcpserverip=self.tcpclient_ip,
            client_port=self.server_port, server_port=self.client_port,
            # self.rcv_token
        )
        # we lose the addrid in opposite direction
        # res.addrid = self.addrid
        # raise Exception("check for rcv_token")
        return res

    def mptcp_dest_from_tcpdest(self, tcpdest: ConnectionRoles):
        return self.mptcpdest if tcpdest == ConnectionRoles.Server else swap_role(self.mptcpdest)

    def generate_mptcp_direction_query(self, mptcpdest: ConnectionRoles):
        """
        Filter packets according to their MPTCP destination
        """
        # for now we assume that TcpConnection are always created with the Server
        # as destination
        tcpdest = ConnectionRoles.Server
        if self.mptcpdest != mptcpdest:
            # t = self.reversed()
            tcpdest = swap_role(tcpdest)

        return super(MpTcpSubflow, self).generate_direction_query(tcpdest)

    def __str__(self):
        """ Plot destination on top of it """
        res = super().__str__()
        res += " (mptcpdest: %s)" % self.mptcpdest
        return res
            # 
            # return super(TcpConnection).generate_direction_query()
        # if dest == ConnectionRoles.Client:
        #     ipsrc = self.tcpserver_ip
        #     server_port = self.server_port
        # else:
        #     ipsrc = self.tcpclient_ip
        #     server_port = self.client_port

        # q += " and ipsrc=='%s' and server_port==(%d) " % (ipsrc, server_port)
        # return q



class MpTcpConnection:
    """
    Holds key characteristics of an MPTCP connection: keys, tokens, subflows

    This should be created via :member:`.build_from_dataframe`

    subflows can be any order
    """
    def __init__(self,
            mptcpstreamid: int,
            client_key: int, client_token: int, server_key: int,
            server_token, subflows, **kwargs) -> None:
        """
        """
        self.mptcpstreamid = mptcpstreamid
        self._subflows = subflows
        self.keys = {
            ConnectionRoles.Client: client_key,
            ConnectionRoles.Server: server_key,
        }

        self.tokens = {
            ConnectionRoles.Client: client_token,
            ConnectionRoles.Server: server_token,
        }

    def __contains__(self, key: MpTcpSubflow):
        """
        Mostly an approximation
        """
        return key in self.subflows() or key.reversed() in self.subflows()

    def generate_direction_query(self, mptcpdest: ConnectionRoles) -> str:
        """
        Filter packets according to the mptcp notion of client/server mptcpdest
        this is a bit different of TcpConnection.generate_direction_query and means that
        some subflows 

        Returns
            Query
        """
        queries = []
        for sf in self.subflows():
            # we need to check the tcp destination to match the mptcp one
            # tcpdest = mptcpdest
            # if sf.mptcpdest != mptcpdest:
            #     # TODO tester ca in REPL ?
            #     tcpdest = swap_role(mptcpdest)

            q = " (" + sf.generate_mptcp_direction_query(mptcpdest) + ") "
            # print(q)
            queries.append(q)
        result =  "(mptcpstream==%d and (%s))" % (self.mptcpstreamid, " or ".join(queries))

        # print(result)
        return result

    # TODO add a destination arg
    # @property
    def subflows(self, mptcpdest: ConnectionRoles = ConnectionRoles.Server):
        # 
        # TODO add a destination ?
        # assert 0
        return self._subflows

    @staticmethod
    def build_from_dataframe(ds: pd.DataFrame, mptcpstreamid: int) -> 'MpTcpConnection':
        """
        Instantiates a class that describes an MPTCP connection
        """

        def get_index_of_non_null_values(serie):
            # http://stackoverflow.com/questions/14016247/python-find-integer-index-of-rows-with-nan-in-pandas/14033137#14033137
            # pd.np.nan == pd.np.nan retursn false in panda so one should use notnull(), isnull()
            return serie.notnull().nonzero()[0]


        ds = ds[ds.mptcpstream == mptcpstreamid]
        if len(ds.index) == 0:
            raise MpTcpException("No packet with this mptcp.stream id %r" % mptcpstreamid)

        # this returns the indexes where a sendkey is set :
        res = get_index_of_non_null_values(ds["sendkey"])
        if len(res) < 2:

            raise MpTcpException("Could not find the initial keys (only found %r)" % (res,))

        cid = res[0]
        client_key       = ds["sendkey"].iloc[cid]
        client_token     = ds["expected_token"].iloc[cid]
        server_key       = ds["sendkey"].iloc[res[1]]
        server_token     = ds["expected_token"].iloc[res[1]]
        master_tcpstream = ds["tcpstream"].iloc[0]

        subflows = []

        # we assume this is the first seen sendkey, thus it was sent to the mptcp server
        master_sf = MpTcpSubflow.create_subflow(
            mptcpdest  = ConnectionRoles.Server,
            tcpstreamid= master_tcpstream, 
            tcpclientip= ds['ipsrc'].iloc[cid],
            tcpserverip= ds['ipdst'].iloc[cid],
            client_port      = ds['sport'].iloc[cid], 
            server_port      = ds['dport'].iloc[cid],
            addrid     = 0   # master subflow has implicit addrid 0
        )

        subflows.append(master_sf)
        tcpstreams = ds.groupby('tcpstream')
        for tcpstreamid, subflow_ds in tcpstreams:
            if tcpstreamid == master_tcpstream:
                continue
            res = get_index_of_non_null_values(subflow_ds["recvtok"])
            if len(res) < 1:
                raise MpTcpException("Missing MP_JOIN")

            # assuming first packet is the initial SYN
            row = res[0]
            receiver_token = subflow_ds["recvtok"].iloc[row]

            # if we see the token
            subflow = MpTcpSubflow.create_subflow(
                mptcpdest = ConnectionRoles.Server if receiver_token == server_token else ConnectionRoles.Client,
                tcpstreamid=tcpstreamid,
                tcpclientip=subflow_ds['ipsrc'].iloc[row],
                tcpserverip=subflow_ds['ipdst'].iloc[row],
                client_port=subflow_ds['sport'].iloc[row], 
                server_port=subflow_ds['dport'].iloc[row],
                addrid=None,
                rcv_token=receiver_token,
                )

            subflows.append(subflow)

        result = MpTcpConnection(mptcpstreamid, client_key, client_token,
            server_key, server_token, subflows)
        return result


    @staticmethod
    def filter_ds(data, **kwargs):
        """
        Args:
        Filters a pandas dataset
             data: a Pandas dataset

        direction = client or server
        """
        dat = data
        for field, value in dict(**kwargs).items():
            query = "{field} == '{value}'".format(field=field, value=value)

            log.debug("Running query %s" % query)
            dat = data.query(query)
        return dat


    def __eq__(self, other):
        """
        Ignores
        A NAT/PAT could have rewritten IPs in which case you probably
        should add another function like score
        """
        # print("self=%r", self)
        return self.score(other) == float('inf')

    def score(self, other: 'MpTcpConnection') -> float:
        """
        ALREADY FILTERED dataframes

        Returns:
            a score
            - '-inf' means it's not possible those 2 matched
            - '+inf' means
        """

        score = 0
        if len(self.subflows()) != len(other.subflows()):
            log.debug("FISHY: Datasets contain a different number of subflows (d vs d)" % ())
            score -= 5

        common_sf = []

        if self.keys[ConnectionRoles.Server] == other.keys[ConnectionRoles.Server] and self.keys[ConnectionRoles.Client] == other.keys[ConnectionRoles.Client]:
            log.debug("matching keys => same")
            return float('inf')


        # TODO check there is at least the master
        # with nat, ips don't mean a thing ?
        for sf in self.subflows():
            if sf in other.subflows() or sf.reversed() in other.subflows():
                log.debug("Subflow %s in common" % sf)
                score += 10
                common_sf.append(sf)
            else:
                log.debug("subflows %s doesn't seem to exist in other " % (sf))

        # TODO compare start times supposing cloak are insync ?
        # print( " score of %r" % score)
        return score


    def __str__(self):
        return str(self.mptcpstreamid)

    def __repr__(self):
        res = """
    Server key/token: {skey:>64.0f}/{stoken}
    Client key/token: {ckey}/{ctoken}
    """.format(
            skey=self.keys[ConnectionRoles.Server],
            stoken=self.tokens[ConnectionRoles.Server],
            ckey=self.keys[ConnectionRoles.Client],
            ctoken=self.tokens[ConnectionRoles.Client],
        )

        res += '\n    '.join(map(str, self.subflows()))
        return res


TcpMapping = NamedTuple('TcpMapping', [('mapped', TcpConnection), ("score", float)])


MpTcpMapping = NamedTuple('MpTcpMapping', [('mapped', MpTcpConnection), ("score", float), 
    # make it a dict rather
        ("subflow_mappings", List[Tuple[MpTcpSubflow,TcpMapping]])
    ])

# MpTcpSubflowMapping = NamedTuple('TcpMapping', [('mapped', TcpConnection), ("score", float)])

