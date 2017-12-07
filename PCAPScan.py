# -*- coding: utf-8 -*-
"""
Scan multiple pcap files and aggregate hosts and statistics about them
"""
import dpkt
import sys
import os
import pyshark
from tqdm import tqdm


class PCAPScan:

    def __init__(self):
        print("Init PCAPScan.")
        self.failed = dict()
        self.verbose = True

    def scanPcapDPKT(self, file):
        """
        Scan the given file object for hosts data, collect statistics for each.
        Using dpkt as pcap parser (does not work :( )

        see https://github.com/kbandla/dpkt
        """

        try:
            f = open(file)
            pcap = dpkt.pcap.Reader(f)
            print("SUCCESS ", file.name)

        except:
            #FIXME: do not throw everything here (also Strg + c from outside)
            e = sys.exc_info()
            self.failed[os.path.abspath(file.name)] = e[1]
            print(
                "FAILED {}, {}".format(
                    e[1], os.path.abspath(file.name)
                )
            )

    def scanPcapPyshark(self, file):
        """
        Scan the given file object for hosts data, collect statistics for each.
        Using dpkt as pcap parser (does work :) )

        see https://github.com/KimiNewt/pyshark
        https://thepacketgeek.com/pyshark-using-the-packet-object/

        If a exception is thrown the same error is shown in wireshark
        """

        try:
            cap = pyshark.FileCapture(
                os.path.abspath(file.name),
                only_summaries=False)
            count = 0
            cap.set_debug()

            # packages can accessed by loop
            print("\nProcessing {}".format(file.name))
            for pkt in tqdm(cap):
                count += 1

                if self.verbose:
                    self.print_conversation_header(pkt)
                #TODO: implement collecting stats!!

            # or a function can be applied on each
            #cap.apply_on_packets(self.print_conversation_header, timeout=10000)

        except KeyboardInterrupt:
            print("Bye")
            sys.exit()

        except:
            e = sys.exc_info()
            self.failed[os.path.abspath(file.name)] = e[1]
            print("FAILED {}, {}".format(e[1], os.path.abspath(file.name)))

    def print_conversation_header(self, pkt):
        try:
            protocol = pkt.transport_layer
            src_addr = pkt.ip.src
            src_port = pkt[pkt.transport_layer].srcport
            dst_addr = pkt.ip.dst
            dst_port = pkt[pkt.transport_layer].dstport
            print(
                '{}  {}:{} --> {}:{}'.
                format(
                    protocol, src_addr, src_port, dst_addr, dst_port
                )
            )
        except AttributeError as e:
            #ignore packets that aren't TCP/UDP or IPv4
            pass
