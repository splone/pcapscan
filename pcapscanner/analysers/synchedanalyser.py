from multiprocessing import Manager


class SynchedAnalyser:

    def __init__(self):
        self.lock = Manager().Lock()
        super().__init__()

    def apply(self, pkt):
        with self.lock:
            self.do(pkt)
