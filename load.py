#!/usr/bin/env python
import dpkt
import socket
import binascii
from collections import defaultdict
from random import randint

filename = 'cap1.pcap'
Tval = 200

f = open(filename)
pcap = dpkt.pcap.Reader(f)

first_ts = 0
mptcp_conn = {}
mptcp_conn_count = 0


for counter, (ts, buf) in enumerate(pcap):
    mptcp_capable = 0
    syn_set = 0
    ack_set = 0

    if counter == 0 :
        first_ts = ts
    else:
        ptime = (ts - first_ts)
            

    eth = dpkt.ethernet.Ethernet(buf)
    if (eth.type != 0x0800):
        continue

    ip = eth.data

    #print "%s %s" % (socket.inet_ntoa(ip.src), socket.inet_ntoa(ip.dst))   
    
    if (ip.p != 6):
        continue

    tcp = ip.data    
    #print "port : %d %d" % (tcp.sport, tcp.dport) 

    if tcp.flags & dpkt.tcp.TH_SYN :
        syn_set = 1

    if tcp.flags & dpkt.tcp.TH_ACK :
        ack_set = 1       

    if (tcp.opts):
        opt_list = dpkt.tcp.parse_opts(tcp.opts) 
        #print opt_list 
        for (op, val) in opt_list: 
            if (op == 30):
                mptcp_capable = 1
                #print binascii.hexlify(val[0])
                bytes = map(ord, val)    
                
                subtype = bytes[0] >> 4
                #print subtype 

                
    if (mptcp_capable == 1):
        if (syn_set == 1):
            if (subtype == 0):
                if (ack_set == 0):
                    #print "mptcp connection request"
                    subflow = {}
                    subflow[len(subflow)] = [ip.src, ip.dst, tcp.sport, tcp.dport]
                    mptcp_conn[mptcp_conn_count] = [ip.src, ip.dst, tcp.sport, tcp.dport, subflow]
                    mptcp_conn_count = mptcp_conn_count + 1
                elif (ack_set == 1):
                    #print "mptcp connection established"
                    subflow = {}
                    subflow[len(subflow)] = [ip.src, ip.dst, tcp.sport, tcp.dport]
                    mptcp_conn[mptcp_conn_count] = [ip.src, ip.dst, tcp.sport, tcp.dport, subflow]
                    mptcp_conn_count = mptcp_conn_count + 1



            if (subtype == 1):
                if (ack_set == 0):
                    #print "mptcp join request" 
                    #find the connection
                    for mc, conn in mptcp_conn.items():
                        sflows = conn[4]
                        for sf, flow in sflows.items():
                            if (flow[0] == ip.src) and (flow[1] == ip.dst) and (flow[3] == tcp.dport):
                                sflows[len(sflows)] = [ip.src, ip.dst, tcp.sport, tcp.dport]
                                break;

                elif (ack_set == 1):
                    #print "mptcp subflow established"
                    for mc, conn in mptcp_conn.items():
                        sflows = conn[4]
                        for sf, flow in sflows.items():
                            if (flow[0] == ip.src) and (flow[1] == ip.dst) and (flow[2] == tcp.sport):
                                sflows[len(sflows)] = [ip.src, ip.dst, tcp.sport, tcp.dport]
                                break;                







data_rtt = defaultdict(dict)
packet_rtt = defaultdict(dict)
packet_rtt = {}  #packet number, rtt value
for mc, conn in mptcp_conn.items():
    #print "Connection %d:" % (mc)
    sflows = conn[4]
    for sf, flow in sflows.items():
        #print "  Subflow %d: %s:%s -- %s:%s" % (sf, socket.inet_ntoa(flow[0]),flow[2], socket.inet_ntoa(flow[1]),flow[3])
        data_rtt[flow[2]][flow[3]] = {}






f = open(filename)
pcap = dpkt.pcap.Reader(f)
seqs = {}

for counter, (ts, buf) in enumerate(pcap):
    mptcp_capable = 0
    

    if counter == 0 :
        first_ts = ts
    else:
        ptime = (ts - first_ts) * 1000
            

    
    eth = dpkt.ethernet.Ethernet(buf)
    if (eth.type != 0x0800):
        continue

    ip = eth.data
      
    if (ip.p != 6):
        continue

    tcp = ip.data  


    if tcp.flags & dpkt.tcp.TH_SYN :
        syn_set = 1

    if tcp.flags & dpkt.tcp.TH_ACK :
        ack_set = 1       

    if (tcp.opts):
        opt_list = dpkt.tcp.parse_opts(tcp.opts) 
        for (op, val) in opt_list: 
            if (op == 30):
                mptcp_capable = 1
                bytes = map(ord, val)    
                subtype = bytes[0] >> 4

    if (mptcp_capable == 1) and (subtype == 2):
        data_len = ip.len - ip.__hdr_len__ - (tcp.off * 4)

        # add expected ack in dictionary
        if (data_len > 0) :
            exp_ack = tcp.seq + data_len
            #print '==== %d %d %d' % (counter, tcp.seq, exp_ack)
            data_rtt[tcp.sport][tcp.dport] = seqs
            seqs[exp_ack] = [counter, ptime]

        # check for expected ack in rev dictionary        
        if (ack_set == 1):
            data_rtt[tcp.dport][tcp.sport] = seqs
            if tcp.ack in seqs.keys():
                rtt = ptime - seqs[tcp.ack][1]
                #print "===+++ RTT = %s from ack packet %d" % (rtt, counter+1)
                packet_rtt[counter] = rtt

#print packet_rtt

data_raw = defaultdict(dict)
data_samples = defaultdict(dict)


#print "Connection table:"
for mc, conn in mptcp_conn.items():
    #print "Connection %d:" % (mc)
    sflows = conn[4]
    for sf, flow in sflows.items():
        #print "  Subflow %d: %s:%s -- %s:%s" % (sf, socket.inet_ntoa(flow[0]),flow[2], socket.inet_ntoa(flow[1]),flow[3])
        data_raw[mc][sf] = {}
        data_samples[mc][sf] = {}


first_ts = 0
f = open(filename)
pcap = dpkt.pcap.Reader(f)
for counter2, (ts, buf) in enumerate(pcap):
    mptcp_capable = 0

    if counter2 == 0 :
        first_ts = ts
    else:
        ptime = (ts - first_ts) * 1000
            

    
    eth = dpkt.ethernet.Ethernet(buf)
    if (eth.type != 0x0800):
        continue

    ip = eth.data
      
    if (ip.p != 6):
        continue

    tcp = ip.data  


    if tcp.flags & dpkt.tcp.TH_SYN :
        syn_set = 1

    if tcp.flags & dpkt.tcp.TH_ACK :
        ack_set = 1       

    if (tcp.opts):
        opt_list = dpkt.tcp.parse_opts(tcp.opts) 
        for (op, val) in opt_list: 
            if (op == 30):
                mptcp_capable = 1
                bytes = map(ord, val)    
                subtype = bytes[0] >> 4


    if (mptcp_capable == 1) and (subtype == 2):
        for mc, conn in mptcp_conn.items():
            sflows = conn[4]
            for sf, flow in sflows.items():
                if (flow[0] == ip.src) and (flow[1] == ip.dst) and (flow[2] == tcp.sport) and (flow[3] == tcp.dport): 
                    # save raw data 
                    data = data_raw[mc][sf]
                    if counter2 in packet_rtt.keys():
                        rtt = packet_rtt[counter2]
                    else:
                        rtt = 0
                    #print "== %d" % rtt
                    data[counter2] = [ptime, tcp.win, rtt, ip.len - ip.__hdr_len__ - (tcp.off * 4)]
                    #print "%d = [%d] [%d] %08.3f %d %d %d" % (counter2, mc, sf, ptime, tcp.win, rtt, ip.len - ip.__hdr_len__ - (tcp.off * 4))





'''
#print "CHECKING RAW SAMPLES"
for mc, conn in mptcp_conn.items():
    sflows = conn[4]
    for sf, flow in sflows.items():
        print "Connection %d subflow %d\n" % (mc, sf)
        data = data_raw[mc][sf]
        for p_no, samples in sorted(data.items()):
            print "[%d] %08.3f %d %d %d)" % (p_no, samples[0], samples[1], samples[2], samples[3])

'''










#--------------------------------










# create samples
for mc, conn in mptcp_conn.items():
    sflows = conn[4]
    for sf, flow in sflows.items():
        #print "Creating samples for connection %d subflow %d\n" % (mc, sf)
        data = data_raw[mc][sf]
        # data is list of all samples
        #print "CONN %d SF %d" % (mc ,sf)
        T = int(Tval)
        win = 0
        rtt = 0
        trans = 0
        n = 1
        rtt_n = 0
        sample_no = 0;
        period = 1
        for c, (p_no, samples) in enumerate(sorted(data.items())):
            #print "[Sample %d] [ts %08.3f] %d %d %d " % (p_no, samples[0], samples[1], samples[2], samples[3])
            if (c == 0): 
                start_ts = samples[0]

            if (c!=0) and (samples[0] > start_ts + (T)):
                #save sample
                avg_data = data_samples[mc][sf]
                avg_rtt = 0
                if (rtt_n > 0):
                    avg_rtt = rtt/rtt_n
                avg_data[sample_no] = [win/n, avg_rtt, (trans / T) *1000 ]

                #print "[period %d][packets %d]: %d %d %d" % (period, n, win/n, avg_rtt, trans)
                period = period +1
                win = samples[1]
                rtt = samples[2]
                trans = samples[3]
                n = 1
                rtt_n = 0
                sample_no = sample_no + 1
                start_ts = samples[0]

            else:
                win = win + samples[1]
                rtt = rtt + samples[2]
                trans  = trans + samples[3]
                n = n + 1
                if (samples[2] > 1):
                    rtt_n = rtt_n + 1









# plot
print """
<script src="http://ajax.googleapis.com/ajax/libs/jquery/1.8.3/jquery.min.js"></script>
<script src="http://code.highcharts.com/highcharts.js"></script>
<script src="http://code.highcharts.com/modules/exporting.js"></script>
<script src="/js/themes/dark-unica.js"></script>



<style type="text/css">
h1 {
   color: #269CC0;
   margin: 12px 0;
   font-size: 24px;
   font-family: 'Trebuchet MS', Arial, Helvetica, Sans-Serif;
   font-weight: normal;
   font-style: normal;
}

h2 {
   color: #aaaaaa;
   margin: 12px 0;
   font-size: 20px;
   font-family: 'Trebuchet MS', Arial, Helvetica, Sans-Serif;
   font-weight: normal;
   font-style: normal;
}

h3 {
   color: #aaaaaa;
   margin: 12px 0;
   font-size: 16px;
   font-family: 'Trebuchet MS', Arial, Helvetica, Sans-Serif;
   font-weight: normal;
   font-style: normal;
}
</style>




<script>
$(function () {
    $('#container_window').highcharts({
        chart: {
            type: 'spline'
        },
        title: {
            text: 'Upstream window size'
        },
        xAxis: {
            title: {
                text: 'time'
            }
        },
        yAxis: {
            title: {
                text: 'Upstream Window (bytes)'
            },
        },

        tooltip: {
            pointFormat: '{series.name}: <b>{point.y}</b><br/>',
            valueSuffix: ' B',
            shared: true
        },

        series: [
"""

mc = 0
sf = 0
par = 0
sflows = mptcp_conn[0][4]
for sf, flow in sflows.items():
    print "{"
    print "name : 'Subflow %d'," % (sf +1 ) 
    data = data_samples[mc][sf]
    print " data: ["
    for k, samples in data.items():
        print "[ %d, %d ]," % (k, samples[par])
    print "                      ]" 
    print " }, "
print "]     });"


                   
print "});"
print "</script>"






print """
<script>
$(function () {
    $('#container_rtt').highcharts({
        chart: {
            type: 'spline'
        },
        title: {
            text: 'Upstream RTT'
        },
        xAxis: {
            title: {
                text: 'time'
            }
        },
        yAxis: {
            title: {
                text: 'Upstream RTT (msec)'
            },
            min: 0
        },
        tooltip: {
            pointFormat: '{series.name}: <b>{point.y}</b><br/>',
            valueSuffix: ' msec',
            shared: true
        },
        series: [
"""

mc = 0
sf = 0
par = 1
sflows = mptcp_conn[0][4]
for sf, flow in sflows.items():
    print "{"
    print "name : 'Subflow %d'," % (sf +1 ) 
    data = data_samples[mc][sf]
    print " data: ["
    for k, samples in data.items():
        print "[ %d, %d ]," % (k, samples[par])
    print "                      ]" 
    print " }, "
print "]     });"


                   
print "});"
print "</script>"







print """
<script>
$(function () {
    $('#container_data').highcharts({
        chart: {
            type: 'spline'
        },
        title: {
            text: 'Upstream Throughput'
        },
        xAxis: {
            title: {
                text: 'time'
            }
        },
        yAxis: {
            title: {
                text: 'Upstream Throughput (Bps)'
            },
            min: 0
        },
        tooltip: {
            pointFormat: '{series.name}: <b>{point.y}</b><br/>',
            valueSuffix: ' Bps',
            shared: true
        },

        series: [
"""

mc = 0
sf = 0
par = 2
sflows = mptcp_conn[0][4]
for sf, flow in sflows.items():
    print "{"
    print "name : 'Subflow %d'," % (sf +1 ) 
    data = data_samples[mc][sf]
    print " data: ["
    for k, samples in data.items():
        print "[ %d, %d ]," % (k, samples[par])
    print "                      ]" 
    print " }, "
print "]     });"


                   
print "});"
print "</script>"





print """
<script>
$(function () {
    $('#container_window_down').highcharts({
        chart: {
            type: 'spline'
        },
        title: {
            text: 'Downstream Window'
        },
        xAxis: {
            title: {
                text: 'time'
            }
        },
        yAxis: {
            title: {
                text: 'Downstream Window (Bytes)'
            },
            min: 0
        },
        tooltip: {
            pointFormat: '{series.name}: <b>{point.y}</b><br/>',
            valueSuffix: ' B',
            shared: true
        },
        series: [
"""

mc = 1
sf = 0
par = 0
sflows = mptcp_conn[1][4]
for sf, flow in sflows.items():
    print "{"
    print "name : 'Subflow %d'," % (sf +1 ) 
    data = data_samples[mc][sf]
    print " data: ["
    for k, samples in data.items():
        print "[ %d, %d ]," % (k, samples[par])
    print "                      ]" 
    print " }, "
print "]     });"


                   
print "});"
print "</script>"



print """
<script>
$(function () {
    $('#container_rtt_down').highcharts({
        chart: {
            type: 'spline'
        },
        title: {
            text: 'Downstream RTT'
        },
        xAxis: {
            title: {
                text: 'time'
            }
        },
        yAxis: {
            title: {
                text: 'Downstream RTT (msec)'
            },
            min: 0
        },
        tooltip: {
            pointFormat: '{series.name}: <b>{point.y}</b><br/>',
            valueSuffix: ' msec',
            shared: true
        },

        series: [
"""

mc = 1
sf = 0
par = 1
sflows = mptcp_conn[1][4]
for sf, flow in sflows.items():
    print "{"
    print "name : 'Subflow %d'," % (sf +1 ) 
    data = data_samples[mc][sf]
    print " data: ["
    for k, samples in data.items():
        print "[ %d, %d ]," % (k, samples[par])
    print "                      ]" 
    print " }, "
print "]     });"


                   
print "});"
print "</script>"

print """
<script>
$(function () {
    $('#container_data_down').highcharts({
        chart: {
            type: 'spline'
        },
        title: {
            text: 'Downstream Throughput'
        },
        xAxis: {
            title: {
                text: 'time'
            }
        },
        yAxis: {
            title: {
                text: 'Downstream Throughput (Bps)'
            },
            min: 0
        },
        tooltip: {
            pointFormat: '{series.name}: <b>{point.y}</b><br/>',
            valueSuffix: ' Bps',
            shared: true
        },

        series: [
"""

mc = 1
sf = 0
par = 2
sflows = mptcp_conn[1][4]
for sf, flow in sflows.items():
    print "{"
    print "name : 'Subflow %d'," % (sf +1 ) 
    data = data_samples[mc][sf]
    print " data: ["
    for k, samples in data.items():
        print "[ %d, %d ]," % (k, samples[par])
    print "                      ]" 
    print " }, "
print "]     });"


                   
print "});"
print "</script>"




print """<h1>Connection 1 - Upstream</h2>"""
sflows = mptcp_conn[0][4]
for sf, flow in sflows.items():
    print "<h2>Subflow %d: %s:%s -- %s:%s</h2>" % (sf +1, socket.inet_ntoa(flow[0]),flow[2], socket.inet_ntoa(flow[1]),flow[3])
        
print """   
</br>     
<div id="container_window" style="min-width: 310px; height: 400px; margin: 0 auto"></div>
</br>   
<div id="container_rtt" style="min-width: 310px; height: 400px; margin: 0 auto"></div>
</br>   
<div id="container_data" style="min-width: 310px; height: 400px; margin: 0 auto"></div>
</br>
</br> </br>   
"""

print """<h1>Connection 2 - Downstream</h1>"""
sflows = mptcp_conn[1][4]
for sf, flow in sflows.items():
    print "<h2>Subflow %d: %s:%s -- %s:%s</h2>" % (sf +1, socket.inet_ntoa(flow[0]),flow[2], socket.inet_ntoa(flow[1]),flow[3])

print """
</br>
<div id="container_window_down" style="min-width: 310px; height: 400px; margin: 0 auto"></div>
</br>   
<div id="container_rtt_down" style="min-width: 310px; height: 400px; margin: 0 auto"></div>
</br>   
<div id="container_data_down" style="min-width: 310px; height: 400px; margin: 0 auto"></div>
</br>   </br>   
</br>
"""



print len(mptcp_conn)


if len(mptcp_conn) == 4:
    print """
    <script>
    $(function () {
        $('#container_window_2').highcharts({
            chart: {
                type: 'spline'
            },
            title: {
                text: 'Upstream window size'
            },
            xAxis: {
                title: {
                    text: 'time'
                }
            },
            yAxis: {
                title: {
                    text: 'Upstream Window (bytes)'
                },
            },

            tooltip: {
                pointFormat: '{series.name}: <b>{point.y}</b><br/>',
                valueSuffix: ' B',
                shared: true
            },

            series: [
    """

    mc = 2
    sf = 0
    par = 0
    sflows = mptcp_conn[2][4]
    for sf, flow in sflows.items():
        print "{"
        print "name : 'Subflow %d'," % (sf +1 ) 
        data = data_samples[mc][sf]
        print " data: ["
        for k, samples in data.items():
            print "[ %d, %d ]," % (k, samples[par])
        print "                      ]" 
        print " }, "
    print "]     });"


                       
    print "});"
    print "</script>"






    print """
    <script>
    $(function () {
        $('#container_rtt_2').highcharts({
            chart: {
                type: 'spline'
            },
            title: {
                text: 'Upstream RTT'
            },
            xAxis: {
                title: {
                    text: 'time'
                }
            },
            yAxis: {
                title: {
                    text: 'Upstream RTT (msec)'
                },
                min: 0
            },
            tooltip: {
                pointFormat: '{series.name}: <b>{point.y}</b><br/>',
                valueSuffix: ' msec',
                shared: true
            },
            series: [
    """

    mc = 2
    sf = 0
    par = 1
    sflows = mptcp_conn[2][4]
    for sf, flow in sflows.items():
        print "{"
        print "name : 'Subflow %d'," % (sf +1 ) 
        data = data_samples[mc][sf]
        print " data: ["
        for k, samples in data.items():
            print "[ %d, %d ]," % (k, samples[par])
        print "                      ]" 
        print " }, "
    print "]     });"


                       
    print "});"
    print "</script>"







    print """
    <script>
    $(function () {
        $('#container_data_2').highcharts({
            chart: {
                type: 'spline'
            },
            title: {
                text: 'Upstream Throughput'
            },
            xAxis: {
                title: {
                    text: 'time'
                }
            },
            yAxis: {
                title: {
                    text: 'Upstream Throughput (Bps)'
                },
                min: 0
            },
            tooltip: {
                pointFormat: '{series.name}: <b>{point.y}</b><br/>',
                valueSuffix: ' Bps',
                shared: true
            },

            series: [
    """

    mc = 2
    sf = 0
    par = 2
    sflows = mptcp_conn[2][4]
    for sf, flow in sflows.items():
        print "{"
        print "name : 'Subflow %d'," % (sf +1 ) 
        data = data_samples[mc][sf]
        print " data: ["
        for k, samples in data.items():
            print "[ %d, %d ]," % (k, samples[par])
        print "                      ]" 
        print " }, "
    print "]     });"


                       
    print "});"
    print "</script>"





    print """
    <script>
    $(function () {
        $('#container_window_down_2').highcharts({
            chart: {
                type: 'spline'
            },
            title: {
                text: 'Downstream Window'
            },
            xAxis: {
                title: {
                    text: 'time'
                }
            },
            yAxis: {
                title: {
                    text: 'Downstream Window (Bytes)'
                },
                min: 0
            },
            tooltip: {
                pointFormat: '{series.name}: <b>{point.y}</b><br/>',
                valueSuffix: ' B',
                shared: true
            },
            series: [
    """

    mc = 3
    sf = 0
    par = 0
    sflows = mptcp_conn[3][4]
    for sf, flow in sflows.items():
        print "{"
        print "name : 'Subflow %d'," % (sf +1 ) 
        data = data_samples[mc][sf]
        print " data: ["
        for k, samples in data.items():
            print "[ %d, %d ]," % (k, samples[par])
        print "                      ]" 
        print " }, "
    print "]     });"


                       
    print "});"
    print "</script>"



    print """
    <script>
    $(function () {
        $('#container_rtt_down_2').highcharts({
            chart: {
                type: 'spline'
            },
            title: {
                text: 'Downstream RTT'
            },
            xAxis: {
                title: {
                    text: 'time'
                }
            },
            yAxis: {
                title: {
                    text: 'Downstream RTT (msec)'
                },
                min: 0
            },
            tooltip: {
                pointFormat: '{series.name}: <b>{point.y}</b><br/>',
                valueSuffix: ' msec',
                shared: true
            },

            series: [
    """

    mc = 3
    sf = 0
    par = 1
    sflows = mptcp_conn[3][4]
    for sf, flow in sflows.items():
        print "{"
        print "name : 'Subflow %d'," % (sf +1 ) 
        data = data_samples[mc][sf]
        print " data: ["
        for k, samples in data.items():
            print "[ %d, %d ]," % (k, samples[par])
        print "                      ]" 
        print " }, "
    print "]     });"


                       
    print "});"
    print "</script>"

    print """
    <script>
    $(function () {
        $('#container_data_down_2').highcharts({
            chart: {
                type: 'spline'
            },
            title: {
                text: 'Downstream Throughput'
            },
            xAxis: {
                title: {
                    text: 'time'
                }
            },
            yAxis: {
                title: {
                    text: 'Downstream Throughput (Bps)'
                },
                min: 0
            },
            tooltip: {
                pointFormat: '{series.name}: <b>{point.y}</b><br/>',
                valueSuffix: ' Bps',
                shared: true
            },

            series: [
    """

    mc = 3
    sf = 0
    par = 2
    sflows = mptcp_conn[3][4]
    for sf, flow in sflows.items():
        print "{"
        print "name : 'Subflow %d'," % (sf +1 ) 
        data = data_samples[mc][sf]
        print " data: ["
        for k, samples in data.items():
            print "[ %d, %d ]," % (k, samples[par])
        print "                      ]" 
        print " }, "
    print "]     });"


                       
    print "});"
    print "</script>"




    print """<h1>Connection 1 - Upstream</h2>"""
    sflows = mptcp_conn[2][4]
    for sf, flow in sflows.items():
        print "<h2>Subflow %d: %s:%s -- %s:%s</h2>" % (sf +1, socket.inet_ntoa(flow[0]),flow[2], socket.inet_ntoa(flow[1]),flow[3])
            
    print """   
    </br>     
    <div id="container_window_2" style="min-width: 310px; height: 400px; margin: 0 auto"></div>
    </br>   
    <div id="container_rtt_2" style="min-width: 310px; height: 400px; margin: 0 auto"></div>
    </br>   
    <div id="container_data_2" style="min-width: 310px; height: 400px; margin: 0 auto"></div>
    </br>
    </br> </br>   
    """

    print """<h1>Connection 2 - Downstream</h1>"""
    sflows = mptcp_conn[3][4]
    for sf, flow in sflows.items():
        print "<h2>Subflow %d: %s:%s -- %s:%s</h2>" % (sf +1, socket.inet_ntoa(flow[0]),flow[2], socket.inet_ntoa(flow[1]),flow[3])

    print """
    </br>
    <div id="container_window_down_2" style="min-width: 310px; height: 400px; margin: 0 auto"></div>
    </br>   
    <div id="container_rtt_down_2" style="min-width: 310px; height: 400px; margin: 0 auto"></div>
    </br>   
    <div id="container_data_down_2" style="min-width: 310px; height: 400px; margin: 0 auto"></div>
    </br>   </br>   
    </br>
    """


















































print """<h3> X-axis: sample interval %d msec</h3>""" % T




                 





