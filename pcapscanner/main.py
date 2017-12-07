# -*- coding: utf-8 -*-

"""
Main class collects the list of files from given folder, order them by their
timestamp in filename, open the gzip content and pass the binary pcap content
to package analysis class PCAPScan.
"""

import argparse
import os
import gzip
import csv
from multiprocessing import Pool

from analysers import hosts, conversations
import pcap

ANALYSERS = [hosts.HostCounter, conversations.ConversationCounter]


class Main:

    def __init__(self, outputdir, inputdir):

        # log files
        self.outputdir = outputdir
        self.ignoredLogFileName = \
            os.path.join(outputdir, 'ignored_files.csv')

        # emtpy files
        open(self.ignoredLogFileName, 'w').close()

        # collect error files and exception cause
        self.ignoredFiles = dict()
        if not os.path.isdir(inputdir):
            raise Exception(
                "Folder '{}' does not exist. Aborting."
                .format(inputdir)
            )
        self.inputdir = inputdir

        # initialize all analysers
        self.analysers = [a(self.outputdir) for a in ANALYSERS]

    def _log_errors(self):
        if not self.ignoredFiles:
            return

        with open(self.ignoredLogFileName, 'w') as f:
            w = csv.writer(f)
            w.writerows(self.ignoredFiles.items())

        print("ignored {} files".format(len(self.ignoredFiles)))

    def start(self):
        pcapfiles = pcap.walk(self.inputdir)
        print(
            "Collected list of {} files in {}".
            format(len(pcapfiles), self.inputdir)
        )

        with Pool(processes=4) as pool:

            # go through all files beginning with the oldest
            for fStr in pcapfiles:

                f = open(fStr, 'rb')
                try:
                    with gzip.open(f, 'rb') as g:
                        # test if this is really GZIP, raises exception if not
                        g.peek(1)

                        # analyze the binary pcap file data
                        # asynchronously
#FIXME doesn't work
#                        pool.apply_async(
#                            pcap.process_pcap, (f, self.analysers)
#                        )
                        pcap.process_pcap(f, self.analysers)

                except OSError as e:
                    # error case: add to ignored files with cause, and
                    # continue with next
                    self.ignoredFiles[os.path.abspath(fStr)] = str(e)
                    continue
                finally:
                    f.close()

        # log errors
        self._log_errors()

        # log results
        for a in self.analysers:
            a.log()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Process some integers.'
    )
    parser.add_argument(
        'inputdir',
        help='path to the directory containing the pcaps'
    )
    parser.add_argument(
        '-o', '--outputdir',
        nargs='?',
        default='.',
        help='path to the output directory'
    )

    args = parser.parse_args()
    scanner = Main(
        outputdir=args.outputdir,
        inputdir=args.inputdir
    )
    scanner.start()
