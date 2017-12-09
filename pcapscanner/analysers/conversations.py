from multiprocessing import Manager
import csv
import os

CSVFN = "conversations.csv"

manager = Manager()


def __add_protocol(storage, pkt):
    protocol = str(pkt.protocol)

    if protocol in storage.keys():
        storage[protocol] += 1
    else:
        storage[protocol] = 0


def __add_port(storage, pkt):
    port = str(pkt.port_dst)

    if port not in storage.keys():
        storage[port] = manager.dict()
    __add_protocol(storage[port], pkt)


def __add_dst_addr(storage, pkt):
    dst_addr = str(pkt.ip_dst)

    if dst_addr not in storage.keys():
        storage[dst_addr] = manager.dict()
    __add_port(storage[dst_addr], pkt)


def init():
    setattr(analyse, 'storage', manager.dict())


def log(outputdir):
    fn = os.path.join(outputdir, CSVFN)
    with open(fn, 'w') as f:
        w = csv.writer(f)

        for src_addr, conversation in analyse.storage.items():
            for dst_addr, ports in conversation.items():
                for port, protocols in ports.items():
                    for protocol, counter in protocols.items():
                        w.writerow(
                            ["{src},{dst},{port},{prot}, {c}"
                            .format(
                                src=src_addr,
                                dst=dst_addr,
                                port=port,
                                prot=protocol,
                                c=counter)]
                        )


def analyse(pkt):
    """ Count conversations between hosts. """

    conversations = analyse.storage
    try:
        src_addr = str(pkt.ip_src)

        if src_addr not in conversations.keys():
            conversations[src_addr] = manager.dict()
        __add_dst_addr(conversations[src_addr], pkt)

    except AttributeError as e:
        # ignore packets that aren't TCP/UDP or IPv4
        pass
