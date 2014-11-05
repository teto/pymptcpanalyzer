#! /usr/bin/env python

# Use dpkt. 
# dpkt is primarily a packet creation/parsing library. 

import dpkt
import socket
import struct
import hashlib

import argparse
import sys
import os


# 2-way mapping between subflow and tcp ports
sf_to_pp = {}    # (server token, addr id):(client port, server port)
pp_to_sf = {}    # (client port, server port):(server token, addr id)

pkts_sent = {}   # 'num of packets sent for each subflow'
                 # key is (client port, server port)

bytes_sent = {}   

first_dsn_c = {}    # 'server token': (dsn of first tcp pkt from client)
first_dsn_s = {}    #                 (       first              server)
last_dsn_c = {}     #                 (       last               client)
last_dsn_s = {}     #                 (       last               server)

token_pair = []   # id of a mptcp connection

client_ips =set()
server_ips =set()

TCP_OPT_MPTCP = 30

SUBTYPE_MP_CAPABLE  = 0
SUBTYPE_MP_JOIN     = 1
SUBTYPE_DSS         = 2
SUBTYPE_ADD_ADDR    = 3
SUBTYPE_REMOVE_ADDR = 4

FLAG_DATA_FIN   = 16 
FLAG_M          = 4
FLAG_A          = 1

# mod from /dpkt/tcp.py
def parse_opts(buf):
    """Parse TCP option buffer into a list of (option, data) tuples."""
    opts = []
    l=0
    while buf:
        o = ord(buf[0])     # return byte value which means option_type
        if o > dpkt.tcp.TCP_OPT_NOP:
            try:
                l = ord(buf[1])             # length of option
                d, buf = buf[2:l], buf[l:]  # d:value, move to the next option in buf
            except ValueError:
                opts.append(None) # XXX
                break
        else:
            d, buf = '', buf[1:]
        opts.append((o,l,d))        
    return opts


def parse_ip(ip, index):
    # ip_src = socket.inet_ntoa(ip.src)
    # ip_dst = socket.inet_ntoa(ip.dst)
    # print "%s -> %s" % (ip_src, ip_dst)

    if ip.p != dpkt.ip.IP_PROTO_TCP:
        return
    
    tcp = ip.data

    for opt in parse_opts(tcp.opts):
        (o,l,buf) = opt                   # option type, length, data

        if o == TCP_OPT_MPTCP:
            sport = tcp.sport
            dport = tcp.dport

            subtype = ord(buf[0]) >> 4             # return value of mptcp_subtype
 
            if subtype == SUBTYPE_MP_CAPABLE:
                if l == 20: 
                                    # l = 20 -> 3rd ACK of primary flow
                                    # l = 12 -> SYN and SYN-ACK have 
                    print ""
                    print index
                    print "mptcp handshake: 3rd ack"
                    # # (key_sd, ) = struct.unpack('>Q', buf[2:10] )
                    # (key_rv, ) = struct.unpack('>Q', buf[10:18])
                    # print ("sender's key    = %d " % key_sd ) 
                    # print ("receiver's key  = %d " % key_rv ) 

                    m_a = hashlib.sha1()
                    m_b = hashlib.sha1()  

                    m_a.update(buf[2:10])
                    m_b.update(buf[10:18])

                    hash_a = m_a.digest()
                    hash_b = m_b.digest()
                    
                    tok_a = hash_a[0:4]
                    tok_b = hash_b[0:4]

                    token_a =  struct.unpack('>L', tok_a) [0] 
                    token_b =  struct.unpack('>L', tok_b) [0] 
                    # print token_a
                    # print token_b

                    token_pair.append((token_a,token_b))

                    
                    idsn_a = struct.unpack('>L', hash_a[-4:] ) [0] 
                    idsn_b = struct.unpack('>L', hash_b[-4:] ) [0] 

                    # print ("idsn client = %d" % idsn_a ),
                    # print ("idsn server = %d" % idsn_b )

                    # from wireshark: dsn of first pkt = idsn + 1 
                    # may be like FIN: 
                    # 1-byte marker at start and end of receive window
                    first_dsn_c[token_b] = idsn_a + 1
                    first_dsn_s[token_b] = idsn_b

                    # print "initial subflow"
                    # print ("sport client = %d" % sport ),
                    # print ("dport server = %d" % dport )

                    # add the initial subflow
                    pp_to_sf[(sport, dport)] = (token_b, 0) 
                    sf_to_pp[(token_b, 0)  ] = (sport, dport)


            if subtype == SUBTYPE_DSS:

                flags = ord(buf[1])
                # if (flags & FLAG_M):

                if (flags & FLAG_DATA_FIN):

                    # print ""
                    # print index
                    # print "Data FIN"
                    (data_ack, data_seq) = struct.unpack('>LL', buf[2:10])
 
                    # print ("sport  = %d" % sport ),
                    # print ("dport  = %d" % dport )
                    
                    # print ("last_seq sent = %d" % data_seq ),
                    # print ("last_seq rcv = %d" % (data_ack - 1) )

                    data_len = struct.unpack('>H', buf[14:16]) [0]
                    if (sport, dport) in pp_to_sf:      
                        # if (sp,dp) is a key, this FIN is from client                                  
                        (token_rcv, id) = pp_to_sf[(sport, dport)]
                        # substrate 1, since empty FIN has data_len = 1 
                        last_dsn_c[token_rcv] = data_seq + data_len - 1 
                        last_dsn_s[token_rcv] = data_ack - 1
                    # else:
                    #     print 'bypass this DATA_FIN'

                elif (flags & FLAG_M):
                # normal pkt which has payload

                    if (flags & FLAG_A):
                        a_off = 4
                    else:
                        a_off = 0
                    data_len = struct.unpack('>H', buf[14:16]) [0]


            # if subtype == SUBTYPE_ADD_ADDR:
            #     addr_ID = ord(buf[3])
            #     # addr    = socket.inet_ntoa(buf[4:8])
 

            if subtype == SUBTYPE_MP_JOIN:

                if tcp.flags == dpkt.tcp.TH_SYN:
                    # print ""
                    # print index
                    # print "New subflow Join"

                    token_rcv = struct.unpack('>L', buf[2:6]) [0]
                    addr_id   = ord(buf[1])

                    # print ("sport client = %d" % sport ),
                    # print ("dport server = %d" % dport )

                    # add new subflow
                    pp_to_sf[(sport, dport)] = (token_rcv, addr_id)
                    sf_to_pp[(token_rcv, addr_id)] = (sport, dport)


def main():

    if len(sys.argv) < 2:
        print "usage: %s -d <folder>",sys.argv[0]
        sys.exit(1)

    parser = argparse.ArgumentParser()
    # parser.add_argument('-f', dest="files", nargs='+', required=True)
    parser.add_argument('-d', dest="dir", nargs='+', required=True)
    args = parser.parse_args()

    os.chdir(args.dir[0])
    print os.getcwd()

    # for z in sorted(os.listdir('.')):
    #     if z.endswith('.tar.gz'):
    #         print z

    for trace in sorted(os.listdir('.')):
        if trace.endswith('.pcap'):
            print trace

            f = open(trace)
            p = dpkt.pcap.Reader(file(trace, "rb"))

            print "parsing file... \n"
            index=0

            for ts, data in p:
                index += 1
                ether = dpkt.ethernet.Ethernet(data)

                if  (ether.type == dpkt.ethernet.ETH_TYPE_IP) \
                  or(ether.type == dpkt.ethernet.ETH_TYPE_IP6):
                    ip = ether.data
                    parse_ip(ip, index)

                # if index > 100:
                #     break

    ###### ---- Report results ---- #########

    print "\nFinish parsing \n"

    print ( "\nNumber of mpTCP connections: %d \n" % len(token_pair))

    for tp  in token_pair:
        i = token_pair.index(tp) + 1
        print ("Connection %d:"  % i)

        (client_token, server_token) = tp
        print ("  Token on the client: %d " % client_token)
        print ("  Token on the server: %d " % server_token)


    print "\n\nNumber of bytes successfully exchanged:" 

    for tp  in token_pair:
        i = token_pair.index(tp) + 1

        (client_token, server_token) = tp
        c_s = last_dsn_c[server_token] - first_dsn_c[server_token]
        s_c = last_dsn_s[server_token] - first_dsn_s[server_token]

        print ("Connection %d:  "  % i )

    print ( "\n\nNumber of subflows: %d \n" % len(sf_to_pp))



if __name__== "__main__":
    main()