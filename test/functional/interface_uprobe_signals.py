#!/usr/bin/env python3
# Copyright (c) 2023 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Use uprobes to send SIGKILL / SIGTERM signals in various situations and test
that these don't lead to problem with the shutdown / next startup. """

import subprocess

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
# Test will be skipped if we don't have bcc installed
try:
    from bcc import BPF  # type: ignore[import]
except ImportError:
    pass

bpf_source = """
BPF_ARRAY(counts, int, 1);

int trace_maybe_abort(struct pt_regs *ctx) {
  int key0 = 0;
  counts.increment(key0);
  int *current_count = counts.lookup(&key0);
  if(current_count != NULL && *current_count == XXX) {
    bpf_trace_printk("send signal SIGNAL after: %llu instances", *current_count);
    bpf_send_signal(SIGNAL);
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
        self.extra_args=[['-txindex=1', '-blockfilterindex=1', '-coinstatsindex=1']]
        self.num_nodes = 1
        self.setup_clean_chain = False

    def skip_test_if_missing_module(self):
        self.skip_if_platform_not_linux()
        self.skip_if_no_bitcoind_tracepoints()
        self.skip_if_no_python_bcc()
        self.skip_if_no_bpf_permissions()

    def attach_uprobe(self, num_logprints, signal):
        # Get mangled symbol for function
        executable_path = '../../bin/bitcoind'
        function_name = 'LogPrintStr'
        nm = subprocess.Popen(('nm', '-g', executable_path), stdout=subprocess.PIPE)
        out = subprocess.check_output(('grep', function_name), stdin=nm.stdout)
        symbol = out.split()[2]
        # Attach probe
        bpfstring = bpf_source.replace("XXX", str(num_logprints))
        bpfstring = bpfstring.replace("SIGNAL", str(signal))

        bpf = BPF(text=bpfstring)
        bpf.attach_uprobe(name=executable_path, sym=symbol, fn_name="trace_maybe_abort")
        return bpf

    def stress_init(self, node, num_log_entries, signal):
        finished = False
        bpf = self.attach_uprobe(num_log_entries, signal)
        try:
            node.start()
            node.wait_for_rpc_connection()
            finished = True
            # we've successfully started the node, now trigger another log entry (TODO: find a better method)
            node.wait_for_rpc_connection()
        except:
            self.log.info("aborting as expected")
        bpf.cleanup()
        return finished


    def stress_shutdown(self, node, num_log_entries, signal):
        finished = False
        try:
            node.start()
            node.wait_for_rpc_connection()
            bpf = self.attach_uprobe(num_log_entries, signal)
            node.stop_node()
            finished = True
        except:
            self.log.info("aborting as expected")
        bpf.cleanup()
        return finished


    def run_stresstest(self, mode, signal):
        def check_clean_start():
            """Ensure that node restarts successfully """
            node.start()
            node.wait_for_rpc_connection()
            assert_equal(200, node.getblockcount())

        node = self.nodes[0]
        finished = False
        num_log_entries = 0
        while not finished:
            num_log_entries += 1
            self.stop_node(0)

            self.log.info(f"aborting after:{num_log_entries} logprints")
            if mode == "init":
                finished = self.stress_init(node, num_log_entries, signal)
            elif mode == "shutdown":
                finished = self.stress_shutdown(node, num_log_entries, signal)
            else:
                assert("mode not supported")

            # Check that nothing got corrupted
            check_clean_start()
            self.stop_node(0)
            if finished:
                self.log.info("Finalize test")
                break

        # bpf.trace_print() #TODO: delete


    def run_test(self):
        self.run_stresstest("init", 9) # SIGKILL
        self.run_stresstest("init", 15)  # SIGTERM
        self.run_stresstest("shutdown", 9)  # SIGKILL


if __name__ == '__main__':
    InitStressTest(__file__).main()
