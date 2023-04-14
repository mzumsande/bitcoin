#!/usr/bin/env python3
# Copyright (c) 2020-2021 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from test_framework.test_framework import BitcoinTestFramework
from test_framework.messages import (
    msg_version,
)
from test_framework.p2p import (
    P2PInterface,
    P2P_SERVICES,
    P2P_SUBVERSION,
    P2P_VERSION,
)


class P2PConnectionLimits(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        # scenario : we have 2 inbound slots and allow a maximum of 1 tx-relaying inbound peer
        self.extra_args = [['-maxconnections=13', '-maxfullrelayincoming=1']]  # 11 slots are reserved for outbounds: FR, BR and 1 feeler

    def run_test(self):
        self.test_inbound_limits()

    def create_blocks_only_version(self):
        no_txrelay_version_msg = msg_version()
        no_txrelay_version_msg.nVersion = P2P_VERSION
        no_txrelay_version_msg.strSubVer = P2P_SUBVERSION
        no_txrelay_version_msg.nServices = P2P_SERVICES
        no_txrelay_version_msg.relay = 0
        return no_txrelay_version_msg

    def test_inbound_limits(self):
        node = self.nodes[0]

        self.log.info('Test with 2 inbound slots, one of which allows tx-relay')
        # first connect a full-relay peer. Any second peer inbound will not be
        # accepted, because we have to assume it's a full-relay peer before receiving VERSION.
        node.add_p2p_connection(P2PInterface())

        self.log.info('Connect a full-relay inbound peer - test that second peer triggers eviction of a full-relay peer')
        # Since there is no unprotected peer to evict here, the new peer is dropped instead.
        with node.assert_debug_log(['failed to find a tx-relaying eviction candidate - connection dropped (full)']):
            self.nodes[0].add_p2p_connection(P2PInterface(), send_version=False, wait_for_verack=False, expect_success=False)
        self.wait_until(lambda: len(node.getpeerinfo()) == 1)
        node.disconnect_p2ps()

        self.log.info('Connect a block-relay inbound peer - test that second full relay peer is accepted')
        peer1 = self.nodes[0].add_p2p_connection(P2PInterface(), send_version=False, wait_for_verack=False)
        peer1.send_message(self.create_blocks_only_version())
        peer1.wait_for_verack()
        peer2 = node.add_p2p_connection(P2PInterface())
        self.wait_until(lambda: len(node.getpeerinfo()) == 2)

        self.log.info('Connecting another full-relay peer triggers full-relay specific eviction')
        with node.assert_debug_log(['failed to find a tx-relaying eviction candidate - connection dropped (full)']):
            self.nodes[0].add_p2p_connection(P2PInterface(), send_version=False, wait_for_verack=False, expect_success=False)
        self.wait_until(lambda: len(node.getpeerinfo()) == 2)

        self.log.info('Connecting two block-relay inbound peers will lead to unconditional eviction when a third peer connects.')
        peer2.peer_disconnect()
        peer3 = self.nodes[0].add_p2p_connection(P2PInterface(), send_version=False, wait_for_verack=False)
        peer3.send_message(self.create_blocks_only_version())
        peer3.wait_for_verack()
        self.wait_until(lambda: len(node.getpeerinfo()) == 2)

        # adding a third peer now leads to unconditional eviction, because the full-relay limit isn't breached
        with node.assert_debug_log(['failed to find an eviction candidate - connection dropped (full)']):
            self.nodes[0].add_p2p_connection(P2PInterface(), send_version=False, wait_for_verack=False, expect_success=False)
        self.wait_until(lambda: len(node.getpeerinfo()) == 2)
        node.disconnect_p2ps()


if __name__ == '__main__':
    P2PConnectionLimits().main()
