#!/usr/bin/python3.5
# attempt to do some monkey patching
# sympify can generate symbols from string
# http://docs.sympy.org/dev/modules/core.html?highlight=subs#sympy.core.basic.Basic.subs
from mptcpanalyzer.command import Command

from enum import Enum, IntEnum
import sympy as sp
import argparse
import shlex
import json
import sympy as sy
import cmd
import sys
import logging


log = logging.getLogger("mptcpanalyzer")
log.setLevel(logging.DEBUG)
log.addHandler(logging.StreamHandler())


# TODO 
class MpTcpSubflow:
    def rto():
        """
        """
        pass




class MpTcpCapabilities(Enum):
    """
    string value should be the one found in json's "capabilities" section
    """
    NRSACK = "Non renegotiable ack"
    DAckReplication =   "DAckReplication" 
    OpportunisticRetransmission = "Opportunistic retransmissions"

class OptionSize(IntEnum):
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

class DssAck(IntEnum):
    NoAck = 0
    SimpleAck = 4
    ExtendedAck = 8

class DssMapping(IntEnum):
    NoDss = 4
    Simple = 8
    Extended = 12

def rto(rtt, var):
    return rtt + 4*var

def dss_size(ack : DssAck, mapping : DssMapping, with_checksum: bool=False) -> int:
    """
    """
    size = 4
    size += ack.value
    size += mapping.value
    size += 2 if checksum else 0
    return size

# class MpTcpOverhead(Command):
#     """

#     """

#     def __init__(self):
#         pass

#     def _dss_size(ack : DssAck, mapping : DssMapping, with_checksum: bool=False) -> int:
#         """
#         """
#         size = 4
#         size += ack.value
#         size += mapping.value
#         size += 2 if checksum else 0
#         return size

#     def _overhead_const (total_nb_of_subflows : int):
#         """
#         Returns constant overhead for a connection

#         Mp_CAPABLE + MP_DSSfinal + sum of MP_JOIN
#         """
#         oh_mpc, oh_finaldss, oh_mpjoin, nb_subflows = sp.symbols("OH_{MP_CAPABLE} OH_{Final dss} OH_{MP_JOIN} n")
#         # TODO test en remplacant les symboles
#         # TODO plot l'overhead d'une connexion
#         constant_oh = oh_mpc + oh_finaldss + oh_mpjoin * nb_subflows
#         # look at simpify
#         # .subs(
#         # todo provide a dict
#         constant_oh.evalf()
#         return OptionSize.Capable.value + total_nb_of_subflows * OptionSize.Join.value

#     def do(self, data):
#         parser = argparse.ArgumentParser(description="Plot overhead")
#         parser.add_argument("topologie", action="store", help="File to load topology from")
#         args = parser.parse_args(shlex.split(args))
#         # print("hello world")
#         # json.load()
# # TODO this should be a plot rather than a command
#         print("topology=", args.topology ) 
#         with open(args.topology) as f:
#             j = json.load(f)
#             print("Number of subflows=%d" % len(j["subflows"]))
#             for s in j["subflows"]:
#                 print("MSS=%d" % s["mss"])
# # TODO sy.add varying overhead
#                 # sy.add 
#             print("toto")

#     def help(self):
#         """
#         """
#         print("Allow to generate stats")

#     def complete(self, text, line, begidx, endidx):
#         """
#         """

# # name/value
class HOLTypes(Enum):
    """
    names inspired from  SCTP paper

    """
    GapedAck = "GapAck-Induced Sender Buffer Blocking (GSB)"
    RcvBufferBlocking = "rcv buffer RcvBufferBlocking"
    ReceiverWindowBlocking = "Window-Induced Receiver Buffer Blocking"
    ReceiverReorderingBlocking = "Reordering-Induced Receiver Buffer Blocking"
    # Transmission-Induced Sender Buffer Blocking (TSB)



"""
"""
Event = collections.namedtuple('Event', ['time', 'subflow', 'direction', 'dsn', 'size', 'blocks'])



class MpTcpSender:
    snd_buf_max = 40
    left = 0
    subflows = None
    
    def __init__(self, max_snd_buffer, capabilities, subflows):
        """
        """
        self.rcv_wnd_max = max_rcv_wnd
        self.wnd = self.rcv_wnd_max

    def recv(self, p):
        """
        """
        return

class MpTcpReceiver:
    rcv_wnd_max = 40
    left = 0
    out_of_order
    
    def __init__(self, max_rcv_wnd, capabilities, subflows):
        """
        """
        self.rcv_wnd_max = max_rcv_wnd
        self.wnd = self.rcv_wnd_max

    def available_window(self):
        ooo = 0
        for block in out_of_order:
            ooo += block.size

        return rcv_wnd_max - ooo

    def right_edge(self):
        return self.left + self.rcv_wnd_max

    def in_range(self, dsn, size):
        return dsn >= self.left and dsn < self.right_edge()

    def add_packet(self, p):
        pass

    def recv(self, p):
        """
        @p packet
        return a tuple of packet
        """
        if not self.in_range(p.dsn, p.size):
            raise Exception("Error")

        if p.

        packets = []
        if self.supports(MpTcpCapabilities.DAckReplication):
            for sf in self.subflows:
                e = Event()
                packets.append(e)

        return packets



class MpTcpNumerics(cmd.Cmd):
    """
    """
    def __init__(self, stdin=sys.stdin): 
        """
        stdin 
        """
        self.prompt = "Rdy>"
        # stdin ?
        super().__init__(completekey='tab', stdin=stdin)

    def do_load(self, filename):
        with open(filename) as f:
            self.j = json.load(f)
            print("toto")

    def do_print(self, args):

        print("Number of subflows=%d" % len(self.j["subflows"]))
        for idx,s in enumerate(self.j["subflows"]):
            print(s)
            msg = "Sf {id} MSS={mss} RTO={rto} rtt={rtt}={fowd}+{bowd}".format(
                # % (idx, s["mss"], rto(s["f"]+s["b"], s['var']))
                id=idx,
                rto=rto(s["f"] + s["b"], s["var"]),
                mss=s["mss"],
                rtt=s["f"] + s["b"],
                fowd=s["f"],
                bowd=s["b"],
                )
            print(msg)
            # TODO sy.add varying overhead
            # sy.add 

    def do_cycle(self, args):
        return self._compute_cycle()

    def _compute_cycle(self):
        """
        returns (approximate lcm of all subflows), (perfect lcm ?)
        """
        rtts = list(map(lambda x: x["f"] + x["b"], self.j["subflows"]))
        lcm = rtts.pop()
        print(lcm)
        # lcm = last["f"] + last["b"]
        for rtt in rtts:
            lcm = sp.lcm(rtt, lcm)
        return lcm
        # sp.lcm(rtt)

    def do_compute_constraints(self, args):
        """
        """
        duration = self.compute_cycle()
        pass

    def _compute_constraints(self, duration):
        """
        Options and buffer size are loaded from topologies
        Compute constraints during `duration`
        """
        # sp.symbols("
        # out of order queue
        rcv_ooo = []
        rcv_left, rcv_wnd, rcv_max_wnd = sp.symbols("dsn_{rcv} w_{rcv} w^{max}_{rcv}")

        capabilities = self.j["capabilities"]
        receiver = MpTcpReceiver(self.j["receiver"]["rcv_buffer"], capabilities)
        sender = MpTcpSender(self.j["sender"]["snd_buffer"],capabilities)
        # ds
        # events = time + direction
        # depending on direction, size may
        # http://www.grantjenks.com/docs/sortedcontainers/sortedlistwithkey.html#id1
        import sortedcontainers
        events = sortedcontainers.SortedListWithKey(key=lambda x: x['time'])
        # should be ordered according to time
        # events = []
        nb_of_subflows = len(self.j["subflows"])
        snd_left, snd_cwnd = sp.symbols("")
        w = []
        for e in events:
            if e["time"] > duration:
                print("Duration of simulation finished ! Break out of the loop")
                break
            #
            if e['direction'] == "receiver":
                if 
            elif e['direction'] == "sender":
                pass
            else

                raise Exception("wrong direction")


        print("loop finished")
        return


    def do_q(self, args):
        """
        Quit/exit program
        """
        return True

    # def _overhead_variable(self):
    #     """
    #     depends on MTU and DSS ratio
    #     In RFC6991, it is explicit that MSS does not include the TCP header.
# The fixed size of the TCP header is of 20 bytes. The fixed size of the IPv4
# header is 20 bytes (40 for Ipv6).
# The classic/widely available MSS is 1500 bytes (without Ethernet) hence
# 1500- 40 (IP + TCP) = 1460 is available. 536 octets is the minimum MSS. 1360
    #     We suppose one ack per a dss mapping can cover at most 2^16 = 65536 bytes
        # """
# # TODO try to get the latex for mean
        # n_dack, n_dss, mss, total_bytes, dss_coverage  = sp.symbols("n_{dack} n_{dss} N_{packets} MSS N DSS_{coverage}")
        # nb_of_packets = total_bytes/mss
        # return n_dack* nb_of_packets + n_dss * total_bytes/dss_coverage

    def _overhead(self):
        """
        """
        return _overhead_const + _overead_variable():
            # OH_{MP_CAPABLE} OH_{Final dss} OH_{MP_JOIN} n
        # return OptionSize.Capable.value + total_nb_of_subflows * OptionSize.Join.value

    # def _overhead_const (self, total_nb_of_subflows : int):
    #     """
    #     Returns constant overhead for a connection

    #     Mp_CAPABLE + MP_DSSfinal + sum of MP_JOIN
    #     """
    #     oh_mpc, oh_finaldss, oh_mpjoin, nb_subflows = sp.symbols("OH_{MP_CAPABLE} OH_{Final dss} OH_{MP_JOIN} n")
    #     # TODO test en remplacant les symboles
    #     # TODO plot l'overhead d'une connexion
    #     constant_oh = oh_mpc + oh_finaldss + oh_mpjoin * nb_subflows
    #     return constant_oh
        # look at simpify
        # .subs(
        # todo provide a dict
        # constant_oh.evalf()

    def do_plot_overhead(self, args):
        """
        total_bytes is the x axis,
        y is overhead


oh_mpc
IN
= 12 + 16 + 24 = 52

OH_MPC= 12 + 12 + 24 
OH_MPJOIN= 12 + 16 + 24 = 52
To compute the variable part we can envisage 2 approache
"""
        print("Attempt to plot overhead via sympy")
        # this should a valid sympy expression

        real_nb_subflows = len(self.j["subflows"])
        print("There are %d subflows" % real_nb_subflows)

        oh_mpc, oh_finaldss, oh_mpjoin, nb_subflows = sp.symbols("OH_{MP_CAPABLE} OH_{Final dss} OH_{MP_JOIN} n")

        # this is per subflows
        n_dack, n_dss, mss, total_bytes, dss_coverage  = sp.symbols("n_{dack} n_{dss} N_{packets} MSS N DSS_{coverage}")

        def _const_overhead(): 
            return oh_mpc + oh_finaldss + oh_mpjoin * nb_subflows

        def _variable_overhead():
            """
            this is per subflow
            """
            nb_of_packets = total_bytes/mss

            variable_oh =  n_dack* nb_of_packets + n_dss * total_bytes/dss_coverage
            return variable_oh

        total_oh = self._overhead_const() + self._overhead_variable()
        # sympy_expr.free_symbols returns all unknown variables
        d = {
                oh_mpc: 48,
                oh_mpjoin: 52,
                nb_subflows: len(real_nb_subflows),
                n_dack:
                n_dss:

                }
        # then we substitute what we can (subs accept an iterable, dict/list)
        total_oh.subs(d)
        sp.plotting.Plot(total_oh)


def run():
    parser = argparse.ArgumentParser(
        description='Generate MPTCP stats & plots'
    )
    #  todo make it optional
    parser.add_argument("input_file", action="store",
            help="Either a pcap or a csv file (in good format)."
            "When a pcap is passed, mptcpanalyzer will look for a its cached csv."
            "If it can't find one (or with the flag --regen), it will generate a "
            "csv from the pcap with the external tshark program."
            )
    parser.add_argument("--debug", "-d", action="store_true",
            help="To output debug information")
    parser.add_argument("--batch", "-b", action="store", type=argparse.FileType('r'),
            default=sys.stdin,
            help="Accepts a filename as argument from which commands will be loaded."
            "Commands follow the same syntax as in the interpreter"
            )
    # parser.add_argument("--command", "-c", action="store", type=str, nargs="*", help="Accepts a filename as argument from which commands will be loaded")

    args, unknown_args = parser.parse_known_args(sys.argv[1:])
    analyzer = MpTcpNumerics()
    analyzer.do_load(args.input_file)
    if unknown_args:
        log.info("One-shot command: %s" % unknown_args)
        analyzer.onecmd(' '.join(unknown_args))
    else:
        log.info("Interactive mode")
        analyzer.cmdloop()

if __name__ == '__main__':
    run()
