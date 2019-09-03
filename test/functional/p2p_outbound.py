#!/usr/bin/env python3
# Copyright (c) 2019 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from test_framework.test_framework import BitcoinTestFramework
from test_framework.mininode import P2PInterface
from test_framework.util import assert_equal, p2p_port, rpc_port, mininode_port
from test_framework.messages import msg_addr, CAddress, NODE_NETWORK, NODE_WITNESS

import time


class P2POB(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1

    def setup_network(self):
        self.setup_nodes()

    def test_addr(self):
        NUM_NODES = 10;
        node = self.nodes[0]
        for i in range(NUM_NODES):
            s1 = node.add_listening_conn(P2PInterface(inbound=False))
        time.sleep(3)

        ibpeer = node.add_p2p_connection(P2PInterface())
        msg = msg_addr()
        for i in range(NUM_NODES):
            addr = CAddress()
            addr.time = 100000000
            addr.nServices = NODE_NETWORK | NODE_WITNESS
            addr.ip = "127.0.0.1"
            addr.port = mininode_port(i)
            #print("AddrPort:" + str(addr.port))
            msg.addrs.append(addr)
        ibpeer.send_and_ping(msg)
        ibpeer.peer_disconnect()
        time.sleep(20)
        assert_equal(len(self.nodes[0].getpeerinfo()), 8)
        print(len(self.nodes[0].getpeerinfo()))

        #input("Pause")


    def run_test(self):
        self.test_addr()

if __name__ == '__main__':
    P2POB().main()
