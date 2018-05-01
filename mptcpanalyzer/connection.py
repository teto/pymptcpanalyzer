import pandas as pd
import logging
from mptcpanalyzer import Destination, MpTcpException

from enum import Enum

log = logging.getLogger(__name__)


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
        tcpstreamid,
        clientip, serverip, cport, sport,
        **kwargs
    ):
        self.tcpstreamid = tcpstreamid # type: int
        self.client_ip = clientip
        self.server_ip = serverip
        self.server_port = sport # type: int
        self.client_port = cport # type: int
        self.isn = kwargs.get('isn')


    def generate_direction_query(self, dest: Destination):
        """
        Filter packets according to their destination
        """
        q = "tcpstream==%d " % self.tcpstreamid
        if dest is None:
            return q

        if dest == Destination.Client:
            ipsrc = self.server_ip
            sport = self.server_port
        else:
            ipsrc = self.client_ip
            sport = self.client_port

        q += " and ipsrc=='%s' and sport==(%d) " % (ipsrc, sport)
        return q


    def score(self, other):
        """
        If every parameter is equal, returns +oo
        """
        if (self.server_ip == other.server_ip and
                self.client_ip == other.client_ip and
                self.client_port == other.client_port and
                self.server_port == other.server_port):
                return float('inf')

        # TODO also match on isn
        # TODO more granulary score
        return 0

    def __eq__(self, other):
        """
        Ignores
        A NAT/PAT could have rewritten IPs in which case you probably
        should add another function like score
        """
        return self.score(other) == float('inf')

    @staticmethod
    def create_subflow(tcpid, clientip, ipdst, cport, dport, **kwargs):
        """
        Args:
        """
        sf = MpTcpSubflow(tcpid, clientip, ipdst, cport, dport, **kwargs)
        return sf

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
        result = TcpConnection(tcpstreamid,
            row['ipsrc'], row['ipdst'],
            row['sport'], row['dport']
        )
        log.debug("Created connection %s", result)
        return result



    def reversed(self):
        return self.create_subflow(
            self.tcpstreamid, self.server_ip, self.client_ip,
            self.server_port, self.client_port,
        )

    def __repr__(self):
        return self.__str__()

    def __str__(self):
        line = ("tcp.stream {s.tcpstreamid}: {s.client_ip}:{s.client_port} "
                " <-> {s.server_ip}:{s.server_port} ").format(s=self,)
        return line


class MpTcpSubflow(TcpConnection):

    def __init__(self, *args, addrid=None):
        super().__init__(*args)
        self.addrid = addrid

    def reversed(self):
        res = self.create_subflow(
            self.tcpstreamid, self.server_ip, self.client_ip,
            self.server_port, self.client_port,
        )
        res.addrid = self.addrid
        return res


class MpTcpConnection:
    """
    Holds key characteristics of an MPTCP connection: keys, tokens, subflows

    This should be created via :member:`.build_from_dataframe`
    """
    def __init__(self, mptcpstreamid, client_key, client_token, server_key,
            server_token, subflows, **kwargs):

        self.mptcpstreamid = mptcpstreamid
        self._subflows = subflows
        self.client_key = client_key
        self.client_token = client_token
        self.server_key = server_key
        self.server_token = server_token

    def __contains__(self, key: MpTcpSubflow):
        """
        Mostly an approximation
        """
        return key in self.subflows or key.reversed() in self.subflows

    def generate_direction_query(self, destination: Destination) -> str:
        """

        Returns
            Query
        """
        queries = []
        for sf in self.subflows:
            q = " (" + sf.generate_direction_query(destination) + ") "
            print(q)
            queries.append(q)
        result =  "(mptcpstream==%d and (%s))" % (self.mptcpstreamid, " or ".join(queries))

        print(result)
        return result

    @property
    def subflows(self):
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
            raise MpTcpException("Could not find the initial keys")

        cid = res[0]
        client_key = ds["sendkey"].iloc[cid]
        client_token = ds["expected_token"].iloc[cid]
        server_key = ds["sendkey"].iloc[res[1]]
        server_token = ds["expected_token"].iloc[res[1]]
        # print("client key", client_key, "/", client_token, "/", server_key, server_token)
        master_id = ds["tcpstream"].iloc[0]

        subflows = []
        master_sf = MpTcpSubflow.create_subflow(
            master_id, ds['ipsrc'].iloc[cid], ds['ipdst'].iloc[cid],
            ds['sport'].iloc[cid], ds['dport'].iloc[cid],
            addrid="master", )

        subflows.append(master_sf)
        tcpstreams = ds.groupby('tcpstream')
        for tcpstreamid, subflow_ds in tcpstreams:
            if tcpstreamid == master_id:
                continue
            res = get_index_of_non_null_values(subflow_ds["recvtok"])
            if len(res) < 1:
                raise MpTcpException("Missing MP_JOIN")
            row = res[0]
            token = subflow_ds["recvtok"].iloc[row]
            subflow = MpTcpSubflow.create_subflow(tcpstreamid,
                subflow_ds['ipsrc'].iloc[row], subflow_ds['ipdst'].iloc[row],
                subflow_ds['sport'].iloc[row], subflow_ds['dport'].iloc[row],
                addrid=None)

            if (token == client_token):
                subflow = subflow.reversed()
            subflows.append(subflow)

        result = MpTcpConnection(mptcpstreamid, client_key, client_token,
            server_key, server_token, subflows)
        # log.debug("Creating connection %s", result)
        return result


    @staticmethod
    def filter_ds(data, **kwargs):
        """
        Args:
        Filters a pandas dataset
            :param data: a Pandas dataset
            :param kwargs: Accepted keywords are

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
        if len(self.subflows) != len(other.subflows):
            log.debug("FISHY: Datasets contain a different number of subflows (d vs d)" % ())
            score -= 5

        common_sf = []

        if self.server_key == other.server_key and self.client_key == other.client_key:
            log.debug("matching keys => same")
            return float('inf')


        # TODO check there is at least the master
        # with nat, ips don't mean a thing ?
        for sf in self.subflows:
            # TODO compute a score
            if sf in other.subflows or sf.reversed in other.subflows:
                log.debug("Subflow %s in common" % sf)
                score += 10
                common_sf.append(sf)
            else:
                log.debug("subflows don't match")

        # TODO compare start times supposing cloak are insync ?
        return score


    def __str__(self):
        return str(self.mptcpstreamid)

    def __repr__(self):
        res = """
        Server key/token: {skey}/{stoken}
        Client key/token: {ckey}/{ctoken}
        """.format(
            skey=self.server_key,
            stoken=self.server_token,
            ckey=self.client_key,
            ctoken=self.client_token,
        )

        return res
