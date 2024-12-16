#!/usr/bin/env python3
# Copyright (c) 2014-2021 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test running bitcoind with -reindex and -reindex-chainstate options.

- Start a single node and generate 3 blocks.
- Stop the node and restart it with -reindex. Verify that the node has reindexed up to block 3.
- Stop the node and restart it with -reindex-chainstate. Verify that the node has reindexed up to block 3.
- Verify that out-of-order blocks are correctly processed, see LoadExternalBlockFile()
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.messages import MAGIC_BYTES
from test_framework.util import (
    assert_equal,
    util_xor,
)


class PruneReorgTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.extra_args = [['-fastprune=1', '-prune=1'], []]
        self.num_nodes = 2

    def run_test(self):
        node0 = self.nodes[0]
        node1 = self.nodes[1]
        self.generate(node1, 700)
        self.disconnect_nodes(0, 1)

        # node 1 creates an alternate chain forking at block 1
        invalid_block = node1.getblockhash(1)
        node1.invalidateblock(invalid_block)
        self.generate(node1, 710, sync_fun=self.no_op)
        self.log.info("MZ prune")
        print(node0.pruneblockchain(400))

        self.log.info("MZ submit blocks")
        for height in range(710):
            block =  node1.getblock(blockhash=node1.getblockhash(height + 1), verbosity=0)
            node0.submitblock(block)



if __name__ == '__main__':
    PruneReorgTest(__file__).main()
