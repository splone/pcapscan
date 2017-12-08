import os

from analysers.synchedanalyser import SynchedAnalyser
from analysers.csvanalyser import CsvAnalyser

CSV = "hostcounter.csv"


class HostCounter(SynchedAnalyser, CsvAnalyser):

    def __init__(self, outputdir):
        self.hosts = dict()
        self.csvfile = os.path.join(outputdir, CSV)
        super().__init__()

    def do(self, pkt):

        try:
            src_addr = pkt.ip.src
            dst_addr = pkt.ip.dst

            if src_addr in self.hosts:
                self.hosts[src_addr] += 1
            else:
                self.hosts[src_addr] = 1

            if dst_addr in self.hosts:
                self.hosts[dst_addr] += 1
            else:
                self.hosts[dst_addr] = 1

        except AttributeError as e:
            # ignore packets that aren't TCP/UDP or IPv4
            pass

    def log(self):
        super().log(self.hosts.items())
