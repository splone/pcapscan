import os
import re
import sys
import gzip
import dpkt
import socket
from tqdm import tqdm
from datetime import datetime as dt
from elasticsearch import Elasticsearch


def walk(directory):
    """ collect all files from a given folder """
    regex = '.*pcap'
    pcapFilesUnordered = [
        os.path.join(dp, f) for dp, dn, filenames
        in tqdm(os.walk(directory)) for f in filenames
        if re.match(regex, os.path.basename(f))
    ]

    return pcapFilesUnordered


def parser_dpkt(pcapfile, progressbar_position):
    """
    Parsing the RawIP encapsulated PCAPs using dpkt. Expects an
    unpacked file ref.
    https://pypi.python.org/pypi/dpkt
    """

    try:
        pcap = dpkt.pcap.Reader(pcapfile)
        es = Elasticsearch()
        es.indices.create(index='packet', ignore=400, body={
            "packet": {
                "properties": {
                    "ip_src": {"type": "ip"},
                    "ip_dst": {"type": "ip"},
                    "timestamp": {"type": "date"},
                    "port_src": {"type": "integer"},
                    "port_dst": {"type": "integer"}
                }
            }
        })

        for ts, buf in tqdm(
            pcap,
            position=progressbar_position,
            unit=" packages",
            desc=os.path.basename(pcapfile.name)
        ):
            try:
                ip = dpkt.ip.IP(buf)
                tcp = ip.data

                es.index(index="packets", body={
                    "protocol": ip.p,
                    "ip_src": socket.inet_ntop(socket.AF_INET, ip.src),
                    "port_src": tcp.sport,
                    "ip_dst": socket.inet_ntop(socket.AF_INET, ip.dst),
                    "port_dst": tcp.dport,
                    "mac_src": "unknown",
                    "mac_dst": "unknown",
                    "pcap_file": os.path.abspath(pcapfile.name),
                    "timestamp": dt.utcfromtimestamp(ts)
                }, doc_type='packet')

            except AttributeError:
                # ignore packets that aren't TCP/UDP or IPv4
                pass

    except KeyboardInterrupt:
        raise
    finally:
        pcapfile.close()


def process_pcap(pcapfilename, progressbar_position):
    """
    Scan the given file object for hosts data, collect statistics for each.
    Using pypacker as parser
    """

    f = open(pcapfilename, 'rb')
    try:
        # test if it is a pcap.gz
        g = None
        try:
            g = gzip.open(f, 'rb')
            # test if this is really GZIP, raises exception if not
            g.peek(1)
            # if it is a gzipped files pass the unpacked file
            # reference to the parser
            f = g
        except:
            # TODO: remove! just for debug
            # print("THIS IS NOT A GZIP FILE: ",pcapfilename)
            pass

        parser_dpkt(f, progressbar_position)

    except KeyboardInterrupt:
        sys.exit()
    finally:
        if g is not None:
            g.close()
        f.close()
