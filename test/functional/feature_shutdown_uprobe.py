#!/usr/bin/env python3
# Copyright (c) 2021 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Stress tests related to node shutdown."""
import os
import subprocess
from pathlib import Path

from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.test_node import ErrorMatch
from test_framework.util import assert_equal
try:
    from bcc import BPF # type: ignore[import]
except ImportError:
    pass

bpf_source = """
BPF_ARRAY(counts, int, 1);

int trace_killme(struct pt_regs *ctx) {
  int key0 = 0;
  int val;
  counts.increment(key0);
  int *current_count = counts.lookup(&key0);
  if(current_count != NULL && *current_count == XXX)
  {
    bpf_trace_printk("SIGKILL after: %llu instances", *current_count);
    bpf_send_signal(9);
  }
  return 0;
}
"""



class InitStressTest(BitcoinTestFramework):
    """
    Ensure that initialization can be interrupted at a number of points and not impair
    subsequent starts.
    """

    def set_test_params(self):
        self.setup_clean_chain = False
        self.num_nodes = 1
        self.extra_args=[['-txindex=1', '-blockfilterindex=1', '-coinstatsindex=1']]

    def run_test(self):

        def check_clean_start():
            """Ensure that node restarts successfully after various interrupts."""
            node.start()
            node.wait_for_rpc_connection()
            assert_equal(200, node.getblockcount())

        def makeBpf(num):
            return bpf_source.replace("XXX", str(num))

        # add some addresses
        for i in range(10000):
            first_octet = i >> 8
            second_octet = i % 256
            a = "{}.{}.1.1".format(first_octet, second_octet)
            self.nodes[0].addpeeraddress(a, 8333)

        for i in range(1,100):
            self.stop_node(0)
            node = self.nodes[0]
            bpfstring = makeBpf(i)
            # get mangled symbol for function
            nm = subprocess.Popen(('nm', '-g', '../../src/bitcoind'), stdout=subprocess.PIPE)
            out = subprocess.check_output(('grep', 'LogPrintStr'), stdin=nm.stdout)
            symbol = out.split()[2]

            node.start()
            node.wait_for_rpc_connection()
            bpf = BPF(text=bpfstring)
            print(f"aborting after:{i} logprints")
            #print(node.getnodeaddresses(0))
            aborted = False
            try:
                bpf.attach_uprobe(name="../../src/bitcoind", sym=symbol, fn_name="trace_killme")
                node.stop_node()
            except:
                print("aborting as expected")
                aborted = True
            bpf.cleanup()
            if not aborted:
                break;

            # Check that the sigkill didn't corrupt anything
            check_clean_start()
            self.stop_node(0)

        #bpf.trace_print()


if __name__ == '__main__':
    InitStressTest().main()
