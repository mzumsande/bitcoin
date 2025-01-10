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
        self.last_block = None
        super().__init__()

    def on_getdata(self, message):
        super().on_getdata(message, wait_time=self.response_time)
        self.last_block = message.inv[-1].hash

    def on_getheaders(self, message):
        pass


class P2PStallingTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1

    def run_test(self):
        #Create some blocks
        NUM_BLOCKS = 10000
        NUM_SLOW_PEERS = 1
        NUM_FAST_PEERS = 7
        node = self.nodes[0]
        tip = int(node.getbestblockhash(), 16)
        blocks = []
        peers = []
        block_list = []
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
            block_list.append(blocks[-1].sha256)

        self.log.info("Connect peers")
        p2p_id = 0
        for _ in range(NUM_SLOW_PEERS):
            p2p_id += 1
            peers.append(node.add_outbound_p2p_connection(TimedPeer(time = 0), p2p_idx=p2p_id, connection_type="outbound-full-relay"))
            self.log.info(f"added slow peer {p2p_id}")

        for _ in range(NUM_FAST_PEERS):
            p2p_id += 1
            peers.append(node.add_outbound_p2p_connection(TimedPeer(time = 0), p2p_idx=p2p_id, connection_type="outbound-full-relay"))
            self.log.info(f"added fast peer {p2p_id}")

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
        block_count = node.getblockcount()
        while (block_count < NUM_BLOCKS):
            time.sleep(2)
            slow_height= block_list.index(peers[0].last_block) + 1
            fast_height = block_list.index(peers[1].last_block) + 1
            block_count = node.getblockcount()
            self.log.info(f"chain: {block_count}/{NUM_BLOCKS} current slow {slow_height} fast {fast_height} dist {fast_height - slow_height}")

        self.log.info("Connection stats:")

        pid =0
        for p in peers:
            self.log.info(f"peer {pid} | connected {p.is_connected}")
            pid += 1

if __name__ == '__main__':
    P2PStallingTest(__file__).main()
