from multiprocessing import Manager
import csv
import os

CSVFN = "conversations.csv"

manager = Manager()


def init():
    setattr(analyse, 'storage', manager.dict())


def log(outputdir):
    fn = os.path.join(outputdir, CSVFN)
    with open(fn, 'w') as f:
        w = csv.writer(f)

        for src_addr, conversation in analyse.storage.items():
            for dst_addr, counter in conversation.items():
                w.writerow(
                    ["{src},{dst},{c}"
                    .format(src=src_addr, dst=dst_addr, c=counter)]
                )


def analyse(pkt):
    """ Count conversations between hosts. """

    conversations = analyse.storage
    try:
        src_addr = str(pkt.ip_src)
        dst_addr = str(pkt.ip_dst)

        if src_addr in conversations.keys():

            if dst_addr in conversations[src_addr].keys():
                conversations[src_addr][dst_addr] += 1
            else:
                conversations[src_addr][dst_addr] = 0

        else:
            #FIXME dict not synced
            conversations[src_addr] = manager.dict()

    except AttributeError as e:
        # ignore packets that aren't TCP/UDP or IPv4
        pass
