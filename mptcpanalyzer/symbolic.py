import enum
import typing
from mptcpanalyzer.topo import SubflowLiveStats

def tcp_rto(rtt, svar):
    return max(200, rtt + 4 * svar)

class OptionSize(enum.IntEnum):
    """
    Size in byte of MPTCP options
    """
    # 12 + 12 + 24
    Capable = 48
    # should be 12 + 16 + 24
    Join = 52
    FastClose = 12
    Fail = 12
    #
    AddAddr4 = 10
    AddAddr6 = 22

    # 3 + n * 1 ?
    # RmAddr


class DssAck(enum.IntEnum):
    NoAck = 0
    SimpleAck = 4
    ExtendedAck = 8


class DssMapping(enum.IntEnum):
    NoDss = 4
    Simple = 8
    Extended = 12

def dss_size(ack: DssAck, mapping: DssMapping, with_checksum: bool = False) -> int:
    """
    Computes the size of a dss depending on the flags
    """
    size = 4
    size += ack.value
    size += mapping.value
    size += 2 if with_checksum else 0
    return size

# TODO should accept a list of mptcp raw subflows ?
def get_rto_buf(subflows: typing.Sequence[SubflowLiveStats]):
    """
    Returns:
        tuple max_rto/buffer_rto
    """
    rtos = map(lambda x: x.rto, subflows)
    max_rto = max(rtos)
    buf_rto = sum(map(lambda x: x.throughput * max_rto, subflows))
    return max_rto, buf_rto

# def get_fastrestransmit_buf(self):
#     """Required buffer as perf the RFC"""
#     subflows = list(self.subflows.values())
#     # rtts = map(lambda x: datetime.timedelta(microseconds=x.rtt), subflows)
#     # max_rtt = max(map(lambda x: x.rtt.microseconds), subflows)

#     # we want in seconds ? depends on througput
#     max_rtt = max(rtts) / 1000
#     buf_fastretransmit = sum(map(lambda x: 2 * x.throughput * max_rtt, subflows))
#     return max_rtt, buf_fastretransmit
