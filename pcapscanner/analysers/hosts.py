import os

CSV = "hostcounter.csv"

def host_counter(pkt):
    hosts = host_counter.storage
    try:
        src_addr = str(pkt.ip.src)
        dst_addr = str(pkt.ip.dst)

        if src_addr in hosts.keys():
            hosts[src_addr] += 1
        else:
            hosts[src_addr] = 1

        if dst_addr in hosts.keys():
            hosts[dst_addr] += 1
        else:
            hosts[dst_addr] = 1

    except AttributeError as e:
        # ignore packets that aren't TCP/UDP or IPv4
        pass
