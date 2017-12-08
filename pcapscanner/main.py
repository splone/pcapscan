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
import time
from contextlib import contextmanager
from multiprocessing import Pool

from analysers import hosts, conversations
import pcap

ANALYSERS = [hosts.HostCounter]

@contextmanager
def timing_context(name):
    startTime = time.time()
    yield
    duration = time.time() - startTime
    if duration < 60:
        print("took {} seconds".format(duration))
    elif duration < 3600:
        print ("took {} minutes, {} seconds".format(int(duration)/60),int(duration)%60)

"""
Dummy function to test multithreading pool
"""
def dummy_func(file):
    print("Process "+file)
    time.sleep(1)

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

    def _log_results(self):
        for a in self.analysers:
            a.log()

    def start(self):
        pcapfiles = pcap.walk(self.inputdir)
        print(
            "Collected list of {} files in {}".
            format(len(pcapfiles), self.inputdir)
        )

        with Pool(processes=4) as pool:
            # async map the process_pcap function to the list of files
            result_queue=pool.map_async(
                dummy_func, [ (f) for f in pcapfiles ]
                #pcap.process_pcap, [ (f) for f in pcapfiles ]
            )
            # start the processing
            results=result_queue.get(len(pcapfiles))

            # The self.analysers reference in the tuple caused the error
            # "TypeError: can't pickle _thread.lock objects"
            # However, the apply method seems to do not work the way
            # it is used here. It does not work with the dummy_func either
            # because it puts all filenames at once into the function at
            # the get call.
#            for fn in pcapfiles:
                # analyze the binary pcap file data
                # asynchronously
#                p = pool.apply(
#                    process_file, (fn)
#                )
#                print(p.get())
        #print("Results",len(results))
        self._log_errors()
        self._log_results()


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
    with timing_context("Processing pcaps in folder {}".format(args.inputdir)):
        scanner.start()
