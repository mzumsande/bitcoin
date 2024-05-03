#!/usr/bin/env python3
# Copyright (c) 2022- The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

# Test the efficiency of the stallign mechanism

import time

from test_framework.test_framework import BitcoinTestFramework

from test_framework.blocktools import (
        create_block,
        create_coinbase
)
from test_framework.messages import (
        MSG_BLOCK,
        MSG_TYPE_MASK,
)
from test_framework.p2p import (
        CBlockHeader,
        msg_block,
        msg_headers,
        P2PDataStore,
)

class TimedPeer(P2PDataStore):
    def __init__(self, time):
        self.response_time = time
        super().__init__()

    def on_getdata(self, message):
        super().on_getdata(message, wait_time=self.response_time)

    def on_getheaders(self, message):
        pass


class P2PStallingTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1

    def run_test(self):
        #Create some blocks
        NUM_BLOCKS = 5000
        NUM_SLOW_PEERS = 2
        NUM_FAST_PEERS = 6
        node = self.nodes[0]
        tip = int(node.getbestblockhash(), 16)
        blocks = []
        peers = []
        height = 1
        block_time = node.getblock(node.getbestblockhash())['time'] + 1
        self.log.info("Prepare blocks without sending them to the node")
        block_dict = {}
        for _ in range(NUM_BLOCKS):
            blocks.append(create_block(tip, create_coinbase(height), block_time))
            blocks[-1].solve()
            tip = blocks[-1].sha256
            block_time += 1
            height += 1
            block_dict[blocks[-1].sha256] = blocks[-1]

        self.log.info("Connect peers")
        p2p_id = 0
        for _ in range(1, NUM_SLOW_PEERS):
            p2p_id += 1
            peers.append(node.add_outbound_p2p_connection(TimedPeer(time = 10), p2p_idx=p2p_id, connection_type="outbound-full-relay"))

        for _ in range(1, NUM_FAST_PEERS):
            p2p_id += 1
            peers.append(node.add_outbound_p2p_connection(TimedPeer(time = 0.1), p2p_idx=p2p_id, connection_type="outbound-full-relay"))

        for peer in peers:
            peer.block_store = block_dict

        num_messages = (len(blocks) + 1999) // 2000
        self.log.info(f"Send {num_messages} headers messages to peer")
        headers_messages = []
        for i in range(num_messages):
            start_idx = i * 2000
            end_idx = min((i + 1) * 2000, NUM_BLOCKS)
            headers_message = msg_headers()
            headers_message.headers = [CBlockHeader(b) for b in blocks[start_idx:end_idx]]
            self.log.info(f"hdr size: {len(headers_message.headers)}")
            headers_messages.append(headers_message)
            for peer in peers:
                peer.send_message(headers_message)

        self.log.info("Wait for all blocks to arrive")
        self.wait_until(lambda: node.getblockcount() >= NUM_BLOCKS - 1, timeout=900)

        self.log.info("Connection stats:")

        pid =0
        for p in peers:
            self.log.info(f"peer {pid} | connected {p.is_connected}")
            pid += 1

if __name__ == '__main__':
    P2PStallingTest(__file__).main()
