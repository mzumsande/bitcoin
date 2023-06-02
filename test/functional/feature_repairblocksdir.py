#!/usr/bin/env python3
# Copyright (c) 2014-2021 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test running bitcoind with -repair-blocksdir option.
"""

import os
import time

from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import ErrorMatch
from test_framework.util import assert_equal


class RepairBlocksDirTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = False
        self.num_nodes = 2

    def setup_network(self):
        self.setup_nodes()

    def run_test(self):
        self.stop_node(0);
        node0 = self.nodes[0]
        node1 = self.nodes[1]
        #perturb data dir
        datadir = os.path.join(self.nodes[0].datadir, self.chain, 'blocks', '')
        target_file = os.path.join(datadir, "blk00000.dat")
        assert os.path.isfile(target_file)
        self.log.info(f"Perturbing blk file to ensure failure {target_file}")
        with open(target_file, "rb") as tf_read:
            contents = tf_read.read()
            tweaked_contents = bytearray(contents)
            tweaked_contents[500:525] = b'1' * 25

        with open(target_file, "wb") as tf_write:
            tf_write.write(bytes(tweaked_contents))

        self.log.info("Test that we corrupted the block database")
        node0.assert_start_raises_init_error(
            extra_args=['-checkblocks=200', '-checklevel=4'],
            expected_msg="Corrupted block database detected",
            match=ErrorMatch.PARTIAL_REGEX)

        self.log.info("Restart with -repairblocksdir to request block from a peer")
        self.restart_node(0, extra_args=['-checkblocks=200', '-checklevel=4', '-repair-blocksdir'])
        self.log.info("Connect a peer")
        self.connect_nodes(0, 1);
        node0.wait_until_stopped(timeout=50)

        self.log.info("Restart without -repairblocksdir and check that the block database is no longer corrupted")
        self.restart_node(0, extra_args=['-checkblocks=200', '-checklevel=2'])


if __name__ == '__main__':
    RepairBlocksDirTest().main()
