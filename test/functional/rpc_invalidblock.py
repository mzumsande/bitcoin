#!/usr/bin/env python3
# Copyright (c) 2014-2021 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from test_framework.test_framework import BitcoinTestFramework
from test_framework.wallet_util import generate_keypair
from test_framework.util import assert_equal

from test_framework.blocktools import (
    create_block,
    create_coinbase,
)

import time


# Tests behaviour of various RPC with respect to invalid blocks
class RPCInvalidBlockRPCTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1

    def create_invalid_block(self, prev, height, time):
        self.coinbase_key, self.coinbase_pubkey = generate_keypair()
        coinbase = create_coinbase(height, self.coinbase_pubkey)
        coinbase.vout[0].nValue += 1
        coinbase.rehash()
        invalid_block = create_block(prev, coinbase, time, version=4)
        invalid_block.solve()
        return invalid_block

    def getchaintip_tests(self):
        n0 = self.nodes[0]
        self.block_time = int(time.time())
        self.log.info("Test getchaintips with invalid block")
        tip = int(n0.getbestblockhash(), 16)
        invalid_block = self.create_invalid_block(tip, 1, self.block_time)

        self.block_time += 1
        block2 = create_block(invalid_block.sha256, create_coinbase(2), self.block_time, version=4)
        block2.solve()

        self.log.info("Submit headers-only chain")
        n0.submitheader(invalid_block.serialize().hex())
        n0.submitheader(block2.serialize().hex())
        tips = n0.getchaintips()
        assert_equal(len(tips), 2)
        assert_equal(tips[0]['height'], 2)
        assert_equal(tips[0]['status'], 'headers-only')

        self.log.info("Submit invalid block to header-only chain")
        n0.submitblock(invalid_block.serialize().hex())
        tips = n0.getchaintips()
        assert_equal(len(tips), 2)
        assert_equal(tips[0]['height'], 2)
        assert_equal(tips[0]['status'], 'invalid')

        self.log.info("Check getchaintips behavior after restart")
        self.restart_node(0)
        tips = n0.getchaintips()
        assert_equal(len(tips), 2)
        assert_equal(tips[0]['height'], 2)
        assert_equal(tips[0]['status'], 'invalid')

    def getblockchaininfo_tests(self):
        n0 = self.nodes[0]
        start_height = 10
        self.generate(n0, start_height)  # generate some block to avoid conflicting with previous tests
        info = n0.getblockchaininfo()
        assert_equal(info['headers'], start_height)
        assert_equal(info['blocks'], start_height)

        self.log.info("Submit a depth-2 headers-only chain and a depth-1 fork")
        tip = int(n0.getbestblockhash(), 16)
        block_time = n0.getblock(n0.getbestblockhash())['time']
        block_time += 1
        invalid_block = self.create_invalid_block(tip, start_height + 1, block_time)

        block_time += 1
        invalid_child = create_block(invalid_block.sha256, create_coinbase(start_height + 2), block_time, version=4)
        invalid_child.solve()

        block_time += 1
        valid_fork = create_block(tip, create_coinbase(start_height + 1), block_time, version=4)
        valid_fork.solve()

        n0.submitheader(invalid_block.serialize().hex())
        n0.submitheader(invalid_child.serialize().hex())
        n0.submitheader(valid_fork.serialize().hex())

        info = n0.getblockchaininfo()
        assert_equal(info['headers'], start_height + 2)
        assert_equal(info['blocks'], start_height)

        self.log.info("Submit first block of the headers-only chain as invalid, and submit valid block")
        n0.submitblock(invalid_block.serialize().hex())
        n0.submitblock(valid_fork.serialize().hex())

        info = n0.getblockchaininfo()
        assert_equal(info['headers'], start_height + 1)
        assert_equal(info['blocks'], start_height + 1)

        self.log.info("Check getblockchaininfo behavior after restart")
        self.restart_node(0)
        info = n0.getblockchaininfo()
        assert_equal(info['headers'], start_height + 1)
        assert_equal(info['blocks'], start_height + 1)

    def run_test(self):
        self.getchaintip_tests()
        self.getblockchaininfo_tests()


if __name__ == '__main__':
    RPCInvalidBlockRPCTest().main()
