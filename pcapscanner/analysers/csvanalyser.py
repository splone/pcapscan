import csv


class CsvAnalyser:

    def __init__(self):
        self.csvfile = ""
        super().__init__()

    def log(self, rows):
        if not self.csvfile:
            return

        with open(self.csvfile, 'w') as f:
            w = csv.writer(f)
            w.writerows(rows)
