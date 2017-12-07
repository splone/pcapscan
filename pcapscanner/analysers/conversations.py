import os

from analysers.synchedanalyser import SynchedAnalyser
from analysers.csvanalyser import CsvAnalyser

CSV = "conversations.csv"


class ConversationCounter(SynchedAnalyser, CsvAnalyser):

    def __init__(self, outputdir):
        self.conversations = dict()
        self.csvfile = os.path.join(outputdir, CSV)
        super().__init__()

    def do(self, pkt):

        try:
            src_addr = pkt.ip.src
            dst_addr = pkt.ip.dst

            if src_addr in self.conversations:

                if dst_addr in self.conversations[src_addr]:
                    self.conversations[src_addr][dst_addr] += 1
                else:
                    self.conversations[src_addr][dst_addr] = 0

            else:
                self.conversations[src_addr] = dict()

        except AttributeError as e:
            # ignore packets that aren't TCP/UDP or IPv4
            pass

    def log(self):
        #TODO log conversations
        import pdb;pdb.set_trace()
        pass
