#!/usr/bin/env python3
# Copyright (c) 2021 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Stress tests related to node initialization."""
import os
import subprocess
from pathlib import Path
import time
import random

from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.test_node import ErrorMatch
from test_framework.util import assert_equal


def wait_for_kill(node, rand_time):
    print("wait started")
    wait_ms = 100
    start_time = time.time_ns();
    while(True):
        if time.time_ns() > start_time + rand_time:
            sigterm_node(node)
            break
        time.sleep(0.001 * wait_ms)
        print("sleeping...")
    print("wait ended")


class InitStressTest(BitcoinTestFramework):
    """
    Idea: Define a procedure under stress.
    Execute it once to get an estimate how long it takes.
    Then send sigkill at random points during that time
    """

    def set_test_params(self):
        self.setup_clean_chain = False
        self.num_nodes = 1
        self.extra_args=[['-coinstatsindex=1']]

    def run_test(self):
        def check_clean_start():
            """Ensure that node restarts successfully after various interrupts."""
            node.start(extra_args=['-coinstatsindex', '-txindex', '-blockfilterindex'])#, '-addrmantest=1'
            node.wait_for_rpc_connection()
            #assert_equal(200, node.getblockcount())

        def func_prepare():
            """Ensure that node restarts successfully after various interrupts."""
            node.start(extra_args=['-coinstatsindex', '-txindex', '-blockfilterindex'])
            node.wait_for_rpc_connection()

        def func_under_test():
            self.generate(node, 2)
            node.dumptxoutset(f"tmp_{random.randint(0, 1000000)}.dat")
            self.generate(node, 2)

        def sigterm_node():
            #node.process.terminate()
            node.process.kill()
            node.process.wait()

        node = self.nodes[0]
        self.stop_node(0)
        func_prepare()
        start_ns = time.time_ns()
        func_under_test()
        end_ns = time.time_ns()
        duration = end_ns - start_ns
        self.log.info(f"Gauged duration: {duration/1E9}s")
        self.log.info("Test run successful")

        for _ in range(100):
            self.stop_node(0)
            rand_time = random.randint(0, duration)
            self.log.info(f"Aborting after {rand_time/1E9} seconds")
            func_prepare()
            with node.wait_until_time(rand_time):
                func_under_test()
            sigterm_node()
            check_clean_start()

if __name__ == '__main__':
    InitStressTest().main()
