import threading


class SynchedAnalyser:

    def __init__(self):
        self.lock = threading.Lock()

    def apply(self, pkt):
        with self.lock:
            self.do(pkt)
