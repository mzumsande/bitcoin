#!/usr/bin/env python3
# Copyright (c) 2020 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import random

from test_framework.test_framework import BitcoinTestFramework

NADDR=200000

class AddrTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1

    def run_test(self):
        self.log.info('Fill up the tried tables of AddrMan')
        for i in range(NADDR):
            a = f"{random.randrange(128,169)}.{random.randrange(1,255)}.{random.randrange(1,255)}.{random.randrange(1,255)}"
            self.nodes[0].addpeeraddress(address=a, tried=True, port=8333)
            if (i%10000 ==0):
                self.log.info(f"Tried: {i} from {NADDR}")
        self.log.info(f"Current size of addrman: {len(self.nodes[0].getnodeaddresses(count=0))}, Max: {(1024+256)*64}")

        self.log.info('Fill up the new tables of AddrMan')
        for i in range(NADDR):
            a = f"{random.randrange(128,169)}.{random.randrange(1,255)}.{random.randrange(1,255)}.{random.randrange(1,255)}"
            self.nodes[0].addpeeraddress(address=a, tried=False, port=8333)
            if (i%10000 ==0):
                self.log.info(f"New: {i} from {NADDR}")

        self.log.info(f"Current size of addrman: {len(self.nodes[0].getnodeaddresses(count=0))}, Max: {(1024+256)*64}")

if __name__ == '__main__':
    AddrTest().main()
