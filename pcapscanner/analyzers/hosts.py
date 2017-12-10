from multiprocessing import Manager
import csv
import os

CSVFN = "hostcounter.csv"

manager = Manager()


def init():
    setattr(analyze, 'storage', manager.dict())


def log(outputdir):
    fn = os.path.join(outputdir, CSVFN)
    with open(fn, 'w') as f:
        w = csv.writer(f)
        w.writerows(analyze.storage.items())


def analyze(pkt):
    """ Count the occurences of all host either as src or dest. """

    hosts = analyze.storage
    try:
        src_addr = str(pkt.ip_src)
        dst_addr = str(pkt.ip_dst)

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
