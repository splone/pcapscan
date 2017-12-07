import csv


class CsvAnalyser:

    def __init__(self):
        self.csvfile = ""

    def log(self, rows):
        if not self.csvfile:
            return

        with open(self.csvfile, 'w') as f:
            w = csv.writer(f)
            w.writerows(rows)
