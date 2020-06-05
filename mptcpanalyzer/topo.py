# from jsonschema import validate
import datetime
import json
from dataclasses import dataclass, field, asdict, InitVar

# eventually copy MpTcpSubflow from mptcpnumerics.py

# Describe what kind of json you expect.
# format Explained at
# https://json-schema.org/understanding-json-schema/
schema = {
    "type": "object",
    "properties": {
        # "description": {"type": "string"},
        "subflows": {"type": "array", "minItems": 1,
            "items": {"$ref": "#/definitions/subflow"}
                     },
        "definitions": {
            "subflow": {
                "type": "object",
                "properties": {
                    "min_rtt": {"type": "number"}
                    # 52460,
                    # "state": "TcpEstablished",
                    # "pacing": 552039,
                    # "dstIp": "3.3.3.2",
                    # "srcPort": 31765,
                    # "rtt_us": 52460,
                    # "rttvar": 26230,
                    # "snd_ssthresh": 2147483647,
                    # "delivery_rate": 0,
                    # "reordering": 3,
                    # "rmem": 1280,
                    # "fowd": 0,
                    # "wmem": 0,
                    # "dstPort": 20756,
                    # "rto_us": 253000,
                    # "cc": "reno",
                    # "snd_cwnd": 10,
                    # "srcIp": "10.0.0.1",
                    # "bowd": 0
                }
            }
        }
    }
}

def load_topology(path):
    """
    """
    with open(path) as fd:
        my_json = json.load(fd)

    # Validate will raise exception if given json is not
    # what is described in schema.
    # validate(instance=my_json, schema=schema)
    return my_json


def to_timedelta(us):
    return datetime.timedelta(microseconds=us)

@dataclass
class SubflowLiveStats:
    """
    Attributes:
        name (str): Identifier of the subflow
        cwnd: careful, there are 2 variables here, one symbolic, one a hard value
        mss: hardcoded mss from topology file
        _state : if packets are inflight or if it is timing out
        fowd:  Forward One Way Delay (OWD)
        bowd: Backward One Way Delay (OWD)
        rttvar: smoothed variance (unused)
        loss_rate: Unused
    """
    # name: str
    app_limited: bool
    mtu: int
    rttvar: int
    delivery_rate: float
    fowd: datetime.timedelta
    bowd: datetime.timedelta
    retrans: int
    snd_cwnd: int
    delivered: int
    lost: int
    tcp_state: str
    ca_state: str
    snd_ssthresh: int
    # rto: int = field(init=False)
    """ use = field(default_factory=False)"""
    min_rtt: datetime.timedelta
    loss_rate: float = field(init=False)

    pacing: InitVar[int]
    rtt_us: InitVar[int]
    rto_us: InitVar[int]

    def __post_init__(self, pacing, rtt_us, rto_us, **kwargs):

        # provide an upperbound to sympy so that it can deduce out of order packets etc...
        # TODO according to SO, it should work without that :/
        print("postinit", rto_us)

        # self.pacing = 0
        self.rtt = datetime.timedelta(microseconds=rtt_us)
        # self.rto = datetime.timedelta(microseconds=rto_us)
        self.min_rtt = datetime.timedelta(microseconds=self.min_rtt)
        self.fowd = to_timedelta(self.fowd)
        self.bowd = to_timedelta(self.bowd)

        """
        This is a pretty crude simulator: it considers that all packets are sent
        at once, hence this boolean tells if the window is inflight
        """

        self.loss_rate = self.lost / self.delivered
        zero_delay = datetime.timedelta(microseconds=0)
        assert self.fowd > zero_delay
        assert self.bowd > zero_delay
        assert self.rtt > zero_delay
        assert self.min_rtt > zero_delay

    @property
    def throughput(self):
        """
        Returns current throughput ?
        """
        return self.delivery_rate
    # self.cwnd_from_file * self.mss / self.rtt


    @property
    def state(self):
        return self._state

    def to_csv(self):
        # todo use asdict
        return {
            "fowd": self.fowd,
            "bowd": self.bowd,
        }

    def __str__(self):
        return "Id={s.name} Rtt={s.fowd}+{s.bowd}".format(
            s=self
        )

    @property
    def rto(self):
        """
        Retransmit Timeout
        """
        return rto(self.rtt, self.rttvar)

    @property
    def rawrtt(self):
        """
        Returns propagation delay instead
        """
        return self.fowd + self.bowd
