#! env/bin/python3
# -*- coding: utf-8 -*-

"""
Main class collects the list of files from given folder, order them by their
timestamp in filename, open the gzip content and pass the binary pcap content
to package analysis class PCAPScan.
"""

import argparse
import sys
import os
import functools
import re
import gzip
import csv

from PCAPScan import PCAPScan
from tqdm import tqdm
from datetime import datetime as dt


class Main:

    def __init__(self, outputdir, inputdir):

        # log files
        self.outputdir = outputdir
        self.ignoredLogFileName = \
            os.path.join(outputdir, 'ignored_files.csv')
        self.resultSummaryFileName = \
            os.path.join(outputdir, 'analysis_pcaps.txt')

        # emtpy files
        open(self.ignoredLogFileName, 'w').close()
        open(self.resultSummaryFileName, 'w').close()

        # collect error files and exception cause
        self.ignoredFiles = dict()
        if not os.path.isdir(inputdir):
            raise Exception(
                "Folder '{}' does not exist. Aborting."
                .format(inputdir)
            )
        self.inputdir = inputdir


    def analyse(self):

        # collect all files below given folder
        regex = '.*pcap'
        pcapFilesUnordered = [
            os.path.join(dp, f) for dp, dn, filenames
            in tqdm(os.walk(self.inputdir)) for f in filenames
            if re.match(regex, os.path.basename(f))
        ]

        print(
            "Collected list of {} files in {}".
            format(len(pcapFilesUnordered), self.inputdir)
        )

        # sort them by timestamp in filename
        self.pcapFiles = sorted(
            pcapFilesUnordered, key=functools.cmp_to_key(self.customSortByDate)
        )

        # start up the scanner
        scanner = PCAPScan()

        # go through all files beginning with the oldest
        for fStr in self.pcapFiles:

            f = open(fStr, 'rb')
            try:
                with gzip.open(f, 'rb') as g:
                    # test if this is really GZIP, raises exception if not
                    g.peek(1)
                    # analyze the binary pcap file data
                    scanner.scanPcapPyshark(f)

            except OSError as e:
                # error case: add to ignored files with cause, and
                # continue with next
                self.ignoredFiles[os.path.abspath(fStr)] = str(e)
                continue
            finally:
                f.close()

        # if files has been ignored tell the user that this happend (and write
        # why into the log file)
        if len(self.ignoredFiles) > 0:
            with open(self.ignoredLogFileName, 'w') as f:
                w = csv.writer(f)
                w.writerows(self.ignoredFiles.items())

            numIgnored = len(self.ignoredFiles)
            percentage = (100.0 / len(self.pcapFiles)) * numIgnored
            print(
                "Ignored {} files of {}. Wrote details to {}.".
                format(
                    numIgnored,
                    len(self.pcapFiles),
                    "({0:.2f}%)".format(percentage),
                    self.ignoredLogFileName
                )
            )

    def customSortByDate(self, a, b):
        """
        Custom sort function to compare them by their timestamp in filename
        """

        regex = '[a-zA-Z0-9\-](2017[0-9-]*)-.*pcap'
        aBase = str(os.path.basename(a))
        bBase = str(os.path.basename(b))
        aDateStr = None
        bDateStr = None

        # parse first filename
        try:
            aDateStr = re.search(regex, aBase).group(1)
        except AttributeError:
            print('Ignore a', aBase)

        # parse second filename
        try:
            bDateStr = re.search(regex, bBase).group(1)
        except AttributeError:
            print('Ignore b', bBase)

        # return nagative value, zero or positive value
        aDate = dt.strptime(aDateStr, "%Y%m%d-%H%M%S")
        bDate = dt.strptime(bDateStr, "%Y%m%d-%H%M%S")

        #print("Compare ",aDate,bDate,(aDate<bDate))
        # compare and sort from oldest to new
        if aDate < bDate:
            return -1

        elif aDate == bDate:
            try:
                # in case date is equal there is a integer before the
                # timestamp to sort
                regex = '[a-zA-Z\-][0-9]\-([0-9]).*'
                numA = int(re.search(regex, aBase).group(1))
                numB = int(re.search(regex, bBase).group(1))

                # also VPN 1 and 2 are present
                regex = '[a-zA-Z\-]([0-9])\-[0-9].*'
                vpnA = int(re.search(regex, aBase).group(1))
                vpnB = int(re.search(regex, bBase).group(1))

            except AttributeError:
                numA = 0
                numB = 0

            #print("fetched numbers ",numA,vpnA,numB,vpnB)
            if numA < numB:
                return -1
            elif numA == numB:
                # should never be the case
                return 0
            else:
                return 1
        else:
            return 1


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
    scanner.analyse()
