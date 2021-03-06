import os
import re
import sys
import gzip
import dpkt
from enum import Enum
from dpkt.compat import compat_ord
import pyshark
import socket

from pypacker import ppcap
from pypacker.layer12 import ethernet
from pypacker.layer3 import ip
from pypacker.layer4 import tcp

import functools
from tqdm import tqdm
from datetime import datetime as dt
from collections import namedtuple

"""
This is the destination format of parsed pcap packages
to decouple PCAP parser data structures from analysers code
"""
ParsedPackage = namedtuple('ParsedPackage', [
    'protocol',
    'ip_src',
    'ip_dst',
    'port_src',
    'port_dst',
    'mac_src',
    'mac_dst',
    'pcap_file',
    'timestamp'
])

class Parser(Enum):
    DPKT = 'dpkt'
    PYPACKER = 'pypacker'
    SCAPY = 'scapy'
    PYSHARK = 'pyshark'


def sort_by_date(a, b):
    """
    Custom sort function to compare them by their timestamp in filename
    """

    regex = '[a-zA-Z0-9\-](2017[0-9-]*)-.*pcap'
    aBase = str(os.path.basename(a))
    bBase = str(os.path.basename(b))
    aDateStr = None
    bDateStr = None

    # parse first filename
    try:
        aDateStr = re.search(regex, aBase).group(1)
    except AttributeError:
        print('Ignore a', aBase)

    # parse second filename
    try:
        bDateStr = re.search(regex, bBase).group(1)
    except AttributeError:
        print('Ignore b', bBase)

    # in case we have no valid timestamp return 0
    if aDateStr is None or bDateStr is None:
        print(
            "sort_by_date: Was not able to extract timestamp comparing {} to {}".
            format(aBase, bBase)
        )
        return 0

    # return nagative value, zero or positive value
    aDate = dt.strptime(aDateStr, "%Y%m%d-%H%M%S")
    bDate = dt.strptime(bDateStr, "%Y%m%d-%H%M%S")

    # compare and sort from oldest to new
    if aDate < bDate:
        return -1

    elif aDate == bDate:
        try:
            # in case date is equal there is a integer before the
            # timestamp to sort
            regex = '[a-zA-Z\-][0-9]\-([0-9]).*'
            numA = int(re.search(regex, aBase).group(1))
            numB = int(re.search(regex, bBase).group(1))

            # also VPN 1 and 2 are present
            regex = '[a-zA-Z\-]([0-9])\-[0-9].*'
            vpnA = int(re.search(regex, aBase).group(1))
            vpnB = int(re.search(regex, bBase).group(1))

        except AttributeError:
            numA = 0
            numB = 0

        if numA < numB:
            return -1
        elif numA == numB:
            # should never be the case
            return 0
        else:
            return 1
    else:
        return 1


def walk(directory):
    """ collect all files from a given folder """
    regex = '.*pcap'
    pcapFilesUnordered = [
        os.path.join(dp, f) for dp, dn, filenames
        in tqdm(os.walk(directory)) for f in filenames
        if re.match(regex, os.path.basename(f))
    ]

    # sort them by timestamp in filename
    return sorted(
        pcapFilesUnordered, key=functools.cmp_to_key(sort_by_date)
    )


def parser_dpkt(pcapfile, progressbar_position):
    """
    Parsing the RawIP encapsulated PCAPs using dpkt. Expects an unpacked file ref.
    https://pypi.python.org/pypi/dpkt
    """
    out=[]
    try:
        pcap = dpkt.pcap.Reader(pcapfile)

        print("SUCCESS ", pcapfile.name)
        for ts,buf in tqdm(
            pcap,
            position=progressbar_position,
            unit=" packages",
            desc=os.path.basename(pcapfile.name)
        ):
            try:
                ip = dpkt.ip.IP(buf)
                tcp = ip.data

                # fetch the infos we need
                # we use socket to convert inet IPv4 IP to human readable IP
                # socket.inet_ntop(socket.AF_INET, inet)
                #FIXME: get MAC adress
                parsedPkg = ParsedPackage(
                            protocol=ip.p,
                            ip_src=socket.inet_ntop(socket.AF_INET, ip.src),
                            port_src=tcp.sport,
                            ip_dst=socket.inet_ntop(socket.AF_INET, ip.dst),
                            port_dst=tcp.dport,
                            mac_src='unknown',
                            mac_dst='unknown',
                            pcap_file=os.path.abspath(pcapfile.name),
                            timestamp=str(dt.utcfromtimestamp(ts))
                )
                out.append(parsedPkg)
            except AttributeError:
                # ignore packets that aren't TCP/UDP or IPv4
                pass
            except ValueError:
                print(
                    "ValueError happend as packages where parsed. We expect RawIP "
                    "encapsulated PCAPs, maybe now we have a Ethernet encapsulated "
                    "one. Abort.")
                raise
    except KeyboardInterrupt:
        raise
    except:
        e = sys.exc_info()
        print("FAILED ", e, str(os.path.abspath(pcapfile.name)))
    finally:
        pcapfile.close()
    return out


def parser_pyshark(pcapfile, progressbar_position):
    """
    Uses tshark CLI in a bash subprocess, parses stdout. Slow but works well with
    pcap.gz and pcap files.
    https://github.com/KimiNewt/pyshark
    """
    out = []
    cap = pyshark.FileCapture(os.path.abspath(pcapfile.name), only_summaries=False)

    # read array (to resolve futures) and return only the information
    # we need to decouple data structures from analysers code
    for pkt in tqdm(
        cap,
        position=progressbar_position,
        unit=" packages",
        desc=os.path.basename(pcapfile.name)
    ):

        try:
            # fetch the infos we need
            parsedPkg = ParsedPackage(
                        protocol=pkt.transport_layer,
                        ip_src=pkt.ip.src,
                        port_src=pkt[pkt.transport_layer].srcport,
                        ip_dst=pkt.ip.dst,
                        port_dst=pkt[pkt.transport_layer].dstport,
                        mac_src="IMPLEMENT",
                        mac_dst="IMPLEMENT",
                        pcap_file=os.path.abspath(pcapfile.name),
                        timestamp=pkt.frame_info.get_field('time')
            )
            out.append(parsedPkg)
        except AttributeError:
            # ignore packets that aren't TCP/UDP or IPv4
            continue
    return out


def parser_pypacker(pcapfile, progressbar_position):
    """
    Does not work!
    Very fast, reads only .pcap (no .gz). Problem is it reads PCAPs with LinkType
    Ethernet, but our dumps are RawIP. We can iterate and print the raw package
    details, but parsing the packages does not work out of the box (because of RawIP).
    https://github.com/mike01/pypacker

    for encapsulation RawIP or Ethernet see here:
    https://osqa-ask.wireshark.org/questions/49568/why-cant-this-wireshark-produced-1-packet-pcap-file-not-be-processed-using-winpcap-or-dpkt
    """
    out = []
    cap = ppcap.Reader(filename=os.path.abspath(pcapfile.name))

    # read array (to resolve futures) and return only the information
    # we need (to reduce memory needed)
    for ts,buf in tqdm(
        cap,
        position=progressbar_position,
        unit=" packages",
        desc=os.path.basename(pcapfile.name)
    ):

        try:
            eth = ethernet.Ethernet(buf)
            print("timestamp {}: {}", ts, eth)
#            for d in eth:
#                print("   datum ",d)
            # FIXME: this works well for PCAPs with LinkType "Ethernet" ,
            #        but not "RawIP" like our dumps.
            if eth[tcp.TCP] is not None:
                print(
                    "{ts}: {src}:{port_src} -> {dst}:{port_dst}".
                    format(
                        ts=ts,
                        src=eth[ip.IP].src_s,
                        port_src=eth[tcp.TCP].sport,
                        dst=eth[ip.IP].dst_s,
                        port_dst=eth[tcp.TCP].dport
                    )
                )

        except AttributeError:
            # ignore packets that aren't TCP/UDP or IPv4
            continue
    cap.close()
    return out


def parser_scapy(pcapfile, progressbar_position):
    """
    Unfinished, never tested
    https://phaethon.github.io/scapy/
    """
    out = []
    with PcapReader(pcapfile.name) as pcap_reader:
      for pkt in pcap_reader:
        #do something with the packet
        pass
    return out


def process_pcap(pcapfilename, analysers, progressbar_position, parser):
    """
    Scan the given file object for hosts data, collect statistics for each.
    Using pypacker as parser
    """
    print("processing {} with {}".format(pcapfilename, parser))

    f = open(pcapfilename, 'rb')
    try:
        # test if it is a pcap.gz
        g = None
        try:
            g = gzip.open(f, 'rb')
            # test if this is really GZIP, raises exception if not
            g.peek(1)
            # if it is a gzipped files pass the unpacked file reference to the parser
            f = g
        except:
            #TODO: remove! just for debug
            #print("THIS IS NOT A GZIP FILE: ",pcapfilename)
            pass

        if parser == Parser.PYSHARK.name:
            # Pyshark CLI is slow but works (single thread ~1.200pkg/s,
            # with 8 threads ~4.500pkg/s)
            parsed_packets = parser_pyshark(f, progressbar_position)

        elif parser == Parser.DPKT.name:
            # DPKT works for pcap and pcap.gz and is fast (single thread ~50.000pkg/s,
            # with 8 threads ~240.000pkg/s)
            parsed_packets = parser_dpkt(f, progressbar_position)

        elif parser == Parser.PYPACKER.name:
            # TODO implement parser
            parsed_packets = parser_pypacker(f, progressbar_position)

        elif parser == Parser.SCAPY.name:
            # TODO implement parser
            parsed_packets = parser_scapy(f, progressbar_position)

        else:
            print("illegal parser")
            return

        #TODO: remove! just for debug
        print(
            "FETCHED {amount} PACKAGES FROM PCAP {dir}.\n  Example: {pkt} ".
            format(
                amount=len(parsed_packets),
                dir=os.path.basename(pcapfilename),
                pkt=parsed_packets[0]
            )
        )

        # process the stats we need
        for p in tqdm(parsed_packets,
                position=progressbar_position,
                ascii=True,
                unit=" packages",
        ):
            for analyser in analysers:
                analyser(p)


    except KeyboardInterrupt:
        print("Bye")
        sys.exit()
    finally:
        if g is not None:
            g.close()
        f.close()
