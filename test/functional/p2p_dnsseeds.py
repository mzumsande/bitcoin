#!/usr/bin/env python3
# Copyright (c) 2020 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework

class P2PDNSSeeds(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1

    def setup_network(self):
        self.setup_nodes()

    def run_test(self):
        self.nodes[0].addpeeraddress("192.0.0.8", 8333) #not reachable
        self.stop_node(0)
        self.start_node(0, extra_args=['-dnsseed=1'])
        with(self.nodes[0].assert_debug_log(expected_msgs=['P2P peers available. Skipped DNS seeding'], timeout=12)):
            for i in range(2):
                #passes everywhere
                #self.nodes[0].add_outbound_p2p_connection(P2PInterface(), p2p_idx=i, connection_type="outbound-full-relay")

                #fails in 22013, passes in master
                self.nodes[0].add_outbound_p2p_connection(P2PInterface(), p2p_idx=i, connection_type="block-relay-only")


if __name__ == '__main__':
    P2PDNSSeeds().main()
