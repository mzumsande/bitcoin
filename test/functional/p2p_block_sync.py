#!/usr/bin/env python3
# Copyright (c) 2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from test_framework.test_framework import BitcoinTestFramework

class BlockSyncTest(BitcoinTestFramework):

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 3

    def setup_network(self):
        self.setup_nodes()

    def run_test(self):
        self.connect_nodes(0, 1) #Test succeeds if I comment this line out!
        # Node 2 (not connected to anyone) generates some blocks
        self.generate(self.nodes[2], 10, sync_fun=self.no_op)
        # connect node 1 and 2 node 1 should request blocks from node2
        self.connect_nodes(1, 2)
        self.sync_blocks(nodes=self.nodes[1:3], timeout=5)
        # but node 1 doesn't send a getheaders msg and doesn't sync because it thinks it's still syncing with node 0 (fSyncStarted=True)
        # even though it could have inferred from the non-full headers msg from node0 that there is nothing more to sync!

if __name__ == '__main__':
    BlockSyncTest().main()
