#!/usr/bin/env python3
# Copyright (c) 2024- The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from test_framework.test_framework import BitcoinTestFramework

class PruneCBITest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.extra_args = [['-fastprune=1', '-prune=1'], []]
        self.num_nodes = 2

    def setup_network(self):
        self.setup_nodes()  # No P2P connection

    def run_test(self):
        node0 = self.nodes[0]
        node1 = self.nodes[1]
        self.generate(node1, 2, sync_fun=self.no_op)
        # Submit a header, and a full block building on it.
        block1 = node1.getblock(blockhash=node1.getblockhash(1), verbosity=0)
        block2 = node1.getblock(blockhash=node1.getblockhash(2), verbosity=0)
        node0.submitheader(block1)
        node0.submitblock(block2)
        # Generate a long chain, forked from genesis
        self.generate(node0, 600, sync_fun=self.no_op)
        # Prune. block2 still has nTx>0
        height = node0.pruneblockchain(300)
        assert(height > -1) # pruning was done

        # Triggers CheckBlockIndex crash: CBI expects, amongst others, m_chain_tx_count to be set for block2
        node0.submitblock(block1)


if __name__ == '__main__':
    PruneCBITest(__file__).main()
