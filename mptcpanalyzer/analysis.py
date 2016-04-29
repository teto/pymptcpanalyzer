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
import collections

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

# TODO make it cleaner with Syn/Ack mentions etc..
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

def rtt(sf):
    return sf["f"] + sf["b"]

def dss_size(ack : DssAck, mapping : DssMapping, with_checksum: bool=False) -> int:
    """
    """
    size = 4
    size += ack.value
    size += mapping.value
    size += 2 if with_checksum else 0
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
# Event = collections.namedtuple('Event', ['time', 'subflow', 'direction', 'dsn', 'size', 'blocks'])

class Event:
    """
    Describe an event in simulator
    """

    time = None
    subflow_id = None
    def __init__(self):
        pass


class SenderEvent(Event):
    dsn = None
    def __init__(self):
        self.direction = Direction.Receiver

class ReceiverEvent(Event):

    dack = None
    rcv_wnd = None
    blocks = []
    def __init__(self):
        self.direction = Direction.Sender



class MpTcpSender:
    """
    By definition of the simulator, a cwnd is either fully outstanding or empty
    """
    snd_buf_max = 40
    snd_next = 0    # left edge of the window/dsn (rename to snd_una ?)
    snd_una = 0
    rcv_wnd = 0 # updated only when
    # subflow congestion windows
    # need to have dsn, cwnd, outstanding ?
    cwnds = {}
    subflows = {}
    
    def __init__(self, config):
        """
        """
        self.snd_buf_max = config["sender"]["snd_buffer"]
        self.left = 0
        # self.wnd = self.
        # self.subflows = config["subflows"]


        for sf in config["subflows"]:
            # TODO update with a symbol
            cwnd = sp.IndexedBase("cwnd")
            self.cwnds.update( {sf["id"]: cwnd})
            self.subflows.update( {sf["id"]: sf})
        # sort them by subflow
        # sp.Symbol()
    
    def generate_pkt(self, sf_id):
        """
        """
        e = SenderEvent()
        sf = self.subflows[sf_id]
        e.time = current_time + sf["f"]
        e.subflow_id = sf_id
        e.dsn  = self.snd_next

        self.snd_next += self.cwnds[""]

        e.size = self.cwnds[sf_id]
        return e


    def recv(self, p):
        """
        Process acks
        pass a bool or function to choose how to increase cwnd ?
        """
        log.debug("Sender received packet")


        # TODO everytime here we should record the constraints
        self.snd_una 
        # cwnd
        return

class Direction(Enum):
    Receiver = 0
    Sender = 1

class MpTcpReceiver:

    rcv_wnd_max = sp.Symbol("W^{receiver}_{MAX}")
    rcv_next = 0
    subflows = {}
    # a list of blocks (dsn, size)
    out_of_order = [] 
    
    def __init__(self, capabilities, config):
        """
        """
        self.config = config
        # self.rcv_wnd_max = max_rcv_wnd
        # self.j["receiver"]["rcv_buffer"]
        # rcv_left, rcv_wnd, rcv_max_wnd = sp.symbols("dsn_{rcv} w_{rcv} w^{max}_{rcv}")
        self.wnd = self.rcv_wnd_max
        for sf in config["subflows"]:
            self.subflows.update( {sf["id"]: sf})

    def available_window(self):
        ooo = 0
        for block in out_of_order:
            ooo += block.size

        return self.rcv_wnd_max - ooo

    def left_edge(self):
        return self.rcv_next

    def right_edge(self):
        return self.left_edge() + self.rcv_wnd_max

    def in_range(self, dsn, size):
        return dsn >= self.left_edge() and dsn + size < self.right_edge()

    def add_packet(self, p):
        pass

    def generate_ack(self, sf_id):
        """
        """
        # super().gen_packet(direction=)
        log.debug("Generating ack for sf_id=%s" % sf_id)
        e = ReceiverEvent()
        e.time = current_time + self.subflows[sf_id]["b"]
        e.ack = self.rcv_next
        return e

    def recv(self, p):
        """
        @p packet
        return a tuple of packet
        """
        # assume it's always in range else we can get an error like 
        # TypeError: cannot determine truth value of Relational
        # if not self.in_range(p.dsn, p.size):
        #     raise Exception("Error")


        log.debug("Receiver received packet")
        packets = []

        if MpTcpCapabilities.DAckReplication in self.config["receiver"]["capabilities"]:
            for sf in self.subflows:
                self.generate_ack()
                e.subflow = p.subflow
                packets.append(e)
        else:
            e = self.generate_ack(p.subflow_id)
            packets.append(e)

        # print(packets)
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
        lcm = sp.ilcm(*rtts)

        # lcm = rtts.pop()
        # print(lcm)
        # # lcm = last["f"] + last["b"]
        # for rtt in rtts:
        #     lcm = sp.lcm(rtt, lcm)
        return lcm
        # sp.lcm(rtt)

    def do_compute_constraints(self, args):
        """
        """
        duration = self._compute_cycle()
        self._compute_constraints(duration)

    def _compute_constraints(self, duration):
        """
        Options and buffer size are loaded from topologies
        Compute constraints during `duration`

        Create an alternative scenario where one flow has an rto

        """

        print("Cycle duration ", duration)
        # sp.symbols("
        # out of order queue
        rcv_ooo = []

        capabilities = self.j["capabilities"]


        # creation of the two hosts
        receiver = MpTcpReceiver(capabilities, self.j)
        sender = MpTcpSender(self.j,) 

        # ds
        # events = time + direction
        # depending on direction, size may
        # http://www.grantjenks.com/docs/sortedcontainers/sortedlistwithkey.html#id1
        import sortedcontainers
        events = sortedcontainers.SortedListWithKey(key=lambda x: x.time)
        # should be ordered according to time
        # events = []
        # nb_of_subflows = len(self.j["subflows"])

        # we start sending a full window over each path
            # sort them depending on fowd
        subflows = sorted(self.j["subflows"] , key=lambda x: x["f"] , reverse=True)

        global current_time
        current_time = 0
        for sf in subflows:
            # TODO check how to insert in 
            log.info("Initial send")
            pkt = sender.generate_pkt(sf["id"])
            events.add(pkt)


        for e in events:
            if e.time > duration:
                print("Duration of simulation finished ! Break out of the loop")
                break
            current_time = e.time
            log.debug("Current time=%d" % current_time)
            # events emitted by host
            pkts = []
            if e.direction == Direction.Receiver:
                pkts = receiver.recv(e)
            elif e.direction == Direction.Sender:
                pkts = sender.recv(e)
            else:
                raise Exception("wrong direction")
            
            print(pkts)
            if pkts:
                for p in pkts:
                    log.debug("Adding event %s"%p)
                    events.add(p)
            else:
                log.debug("No pkt present")

        print("loop finished")
        return


    def do_q(self, args):
        """
        Quit/exit program
        """
        return True

    def do_plot_overhead(self, args):
        """
        total_bytes is the x axis,
        y is overhead
        oh_mpc
        IN
        = 12 + 16 + 24 = 52 OH_MPC= 12 + 12 + 24 
        OH_MPJOIN= 12 + 16 + 24 = 52
        To compute the variable part we can envisage 2 approache
        """
        print("Attempt to plot overhead via sympy")
        # this should a valid sympy expression

        real_nb_subflows = len(self.j["subflows"])
        print("There are %d subflows" % real_nb_subflows)

        oh_mpc, oh_finaldss, oh_mpjoin, nb_subflows = sp.symbols("OH_{MP_CAPABLE} OH_{DFIN} OH_{MP_JOIN} N")

# cls=Idx
        i = sp.Symbol('i', integer=True)
        total_bytes = sp.Symbol('bytes', )
        # nb_subflows = sp.Symbol('N', integer=True)
        # mss = sp.IndexedBase('MSS', i )
        sf_mss = sp.IndexedBase('MSS')
        sf_dss_coverage = sp.IndexedBase('DSS')
        # sf_ratio = sp.IndexedBase('ratio')
        sf_bytes = sp.IndexedBase('bytes')

        # this is per subflows
        n_dack, n_dss  = sp.symbols("S_{dack} S_{dss}") 

        def _const_overhead(): 
            return oh_mpc + oh_finaldss + oh_mpjoin * nb_subflows

        def _variable_overhead():
            """
            this is per subflow
            """

            # nb_of_packets = total_bytes/mss

            variable_oh =  sp.Sum( (n_dack * sf_bytes[i])/sf_mss[i] + n_dss * sf_bytes[i]/sf_dss_coverage[i], (i,1,nb_subflows))
            return variable_oh

        # sum of variable overhead
        variable_oh = _variable_overhead()
        # print("MPC size=", OptionSize.Capable.value,)
        # sympy_expr.free_symbols returns all unknown variables
        d = {
                oh_mpc: OptionSize.Capable.value,
                oh_mpjoin: OptionSize.Join.value,
                oh_finaldss: DssAck.SimpleAck.value,
                nb_subflows: real_nb_subflows,
                # n_dack: nb_of_packets, # we send an ack for every packet
                n_dack: DssAck.SimpleAck.value,
                n_dss:  dss_size(DssAck.NoAck, DssMapping.Simple),
        }


        # TODO substiture indexed values
# http://stackoverflow.com/questions/26402387/sympy-summation-with-indexed-variable 
        # -- START -- 
        # f = lambda x: Subs(
        #         s.doit(), 
        #         [s.function.subs(s.variables[0], j) for j in range(s.limits[0][1], s.limits[0][2] + 1)], 
        #         x
        #         ).doit()
        # f((30,10,2))
        # # -- END --


        # then we substitute what we can (subs accept an iterable, dict/list)
        # subs returns a new expression
        
        total_oh = _const_overhead() + variable_oh 
        # print("latex version=", sp.latex(total_oh))
        # numeric_oh = total_oh.subs(d)

        print("latex version=", sp.latex(variable_oh))
        def _test_matt(s, ratios):
            # print("%r %r" % (s.limits, s.limits[0][0] ) )
            # print(self.j["subflows"][1])
            # print(s.variables[0])
            # print(s.limits[0][0].subs(i, 4) )
            # for z in range(s.limits[0][1], s.limits[0][2] ): 
            for z in range(1,real_nb_subflows+1):
                # print(z)

                print("After substitution s=", s)
                s = s.subs( {
                    sf_mss[z]: self.j["subflows"][z-1]["mss"],
                    # sf_bytes[z]: total_bytes, # self.j["subflows"][i],
                    sf_bytes[z]: ratios[z-1] * total_bytes, # self.j["subflows"][i],
                    sf_dss_coverage[z]: 1500
                }).doit()

            return s.subs({

                n_dack: DssAck.SimpleAck.value,
                n_dss:  dss_size(DssAck.NoAck, DssMapping.Simple),
                })
        variable_oh = variable_oh.subs(nb_subflows,real_nb_subflows)
        test = sp.Rational(1,2)
        var_oh_numeric = _test_matt(variable_oh.doit(), [test,test])


        # numeric_oh.subs(
        print("After substitution=", sp.latex(var_oh_numeric))
        print("After substitution=", sp.latex(var_oh_numeric))
        # print("After substitution=", sp.latex(numeric_oh))
        # print("After substitution=", sp.latex(numeric_oh.doit()))

        # there should be only total_bytes free
        sp.plotting.plot(var_oh_numeric)


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
