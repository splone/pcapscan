#env python3
# -*- coding: utf-8 -*-

"""
Main class collects the list of files from given folder, order them by their
timestamp in filename, open the gzip content and pass the binary pcap content
to package analysis class PCAPScan.
"""

import argparse
import os
import csv
import time
from multiprocessing import Pool

from analyzers import hosts, conversations
import pcap

NUM_THREADS = 4

ANALYZERS = [
    hosts,
    conversations
]

ASCII_LOGO = """

@@@@@@@    @@@@@@@   @@@@@@   @@@@@@@    @@@@@@    @@@@@@@   @@@@@@   @@@  @@@
@@@@@@@@  @@@@@@@@  @@@@@@@@  @@@@@@@@  @@@@@@@   @@@@@@@@  @@@@@@@@  @@@@ @@@
@@!  @@@  !@@       @@!  @@@  @@!  @@@  !@@       !@@       @@!  @@@  @@!@!@@@
!@!  @!@  !@!       !@!  @!@  !@!  @!@  !@!       !@!       !@!  @!@  !@!!@!@!
@!@@!@!   !@!       @!@!@!@!  @!@@!@!   !!@@!!    !@!       @!@!@!@!  @!@ !!@!
!!@!!!    !!!       !!!@!!!!  !!@!!!     !!@!!!   !!!       !!!@!!!!  !@!  !!!
!!:       :!!       !!:  !!!  !!:            !:!  :!!       !!:  !!!  !!:  !!!
:!:       :!:       :!:  !:!  :!:           !:!   :!:       :!:  !:!  :!:  !:!
 ::        ::: :::  ::   :::   ::       :::: ::    ::: :::  ::   :::   ::   ::
 :         :: :: :   :   : :   :        :: : :     :: :: :   :   : :  ::    :

"""

class Main:

    def __init__(self, outputdir, inputdir, parser):

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

        # initialize all analyzers
        for a in ANALYZERS:
            a.init()

        self.parser = parser

    def _log_errors(self):
        if not self.ignoredFiles:
            return

        with open(self.ignoredLogFileName, 'w') as f:
            w = csv.writer(f)
            w.writerows(self.ignoredFiles.items())

        print("ignored {} files".format(len(self.ignoredFiles)))

    def _log_results(self):
        for a in ANALYZERS:
            a.log(self.outputdir)

    def start(self):
        pcapfiles = pcap.walk(self.inputdir)
        print(
            "Collected list of {} files in {}".
            format(len(pcapfiles), self.inputdir)
        )

        with Pool(processes=NUM_THREADS) as pool:
            c = 0
            # async map the process_pcap function to the list of files
            for fn in pcapfiles:
                # for tqdm progress bars
                progressbar_position = c % NUM_THREADS
                c += 1

                # analyze the binary pcap file data
                # asynchronously
                pool.apply_async(
                    pcap.process_pcap,
                    (fn, [a.analyze for a in ANALYZERS], progressbar_position, self.parser)
                )

            # close pool
            pool.close()

            # wait for workers to finish
            pool.join()

        self._log_errors()
        self._log_results()

        # return number of pcap files
        return len(pcapfiles)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='analyzing pcaps for fun an profit'
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
    parser.add_argument(
        '-p', '--parser',
        nargs='?',
        default=pcap.Parser.DPKT.name,
        choices=[p.name for p in pcap.Parser]
    )

    args = parser.parse_args()
    print(ASCII_LOGO)

    scanner = Main(
        outputdir=args.outputdir,
        inputdir=args.inputdir,
        parser=args.parser
    )
    # measure time
    startTime = time.time()

    # do the processing
    processed = scanner.start()

    # output summary of timing
    duration = time.time() - startTime

    if duration < 60:
        print(
            "\n\nProcessing {} pcaps took {:2.2f} seconds"
            .format(processed, duration)
        )
    elif duration < 3600:
        print(
            "\n\nProcessing {} pcaps took {} minutes, {:2.2f} seconds"
            .format(processed, int(duration) / 60, int(duration) % 60)
        )
