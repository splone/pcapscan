import os
import re
import sys
import gzip
import pyshark
import functools
from tqdm import tqdm
from datetime import datetime as dt
from collections import namedtuple

"""
This is the destination format of parsed pcap packages.
We use this to save memory, so we do not need to store
the whole pcap in RAM before analysers start their work.
"""
ParsedPackage = namedtuple('ParsedPackage', [
    'protocol',
    'ip_src',
    'ip_dst',
    'port_src',
    'port_dst',
    'pcap_file'
])


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


def process_pcap(pcapfile, analysers, progressbar_position):
    """
    Scan the given file object for hosts data, collect statistics for each.
    Using pyshark as pcap parser (does work :) )

    see https://github.com/KimiNewt/pyshark
    https://thepacketgeek.com/pyshark-using-the-packet-object/

    If a exception is thrown the same error is shown in wireshark
    """
    print("processing {}".format(pcapfile))

    f = open(pcapfile, 'rb')
    try:
        with gzip.open(f, 'rb') as g:
            # test if this is really GZIP, raises exception if not
            g.peek(1)

        cap = pyshark.FileCapture(
            os.path.abspath(pcapfile),
            only_summaries=False)
        cap.set_debug()

        # read array (to resolve futures) and return only the information
        # we need (to reduce memory needed)
        for pkt in tqdm(
            cap,
            position=progressbar_position,
            unit=" packages",
            desc=os.path.basename(pcapfile)
        ):

            try:
                # fetch the infos we need
                parsedPkg = ParsedPackage(
                            protocol=pkt.transport_layer,
                            ip_src=pkt.ip.src,
                            port_src=pkt[pkt.transport_layer].srcport,
                            ip_dst=pkt.ip.dst,
                            port_dst=pkt[pkt.transport_layer].dstport,
                            pcap_file=pcapfile
                )

            except AttributeError:
                # ignore packets that aren't TCP/UDP or IPv4
                continue

            # process the stats we need
            for analyser in analysers:
                analyser(parsedPkg)

    except KeyboardInterrupt:
        print("Bye")
        sys.exit()
    except Exception as e:
        print(e)
    finally:
        f.close()
