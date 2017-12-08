CSV = "conversations.csv"


def conversation_counter(pkt):
    conversations = conversation_counter.storage

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
            conversations[src_addr] = dict()

    except AttributeError as e:
        # ignore packets that aren't TCP/UDP or IPv4
        pass
