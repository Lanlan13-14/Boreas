#!/usr/bin/env python3
import json
import math
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
import single_core_probe as probe
import single_core_hook as hook


class MetricsTests(unittest.TestCase):
    def test_decimal_gigabit_not_binary_or_bidirectional_sum(self):
        good=probe.summarize_windows([{"seconds":60,"bytes":7_500_000_000}])
        self.assertEqual(good["minimum_window_mbps"],1000)
        self.assertTrue(good["all_windows_gigabit"])
        bad=probe.summarize_windows([{"seconds":60,"bytes":7_500_000_000},{"seconds":60,"bytes":7_499_999_999}])
        self.assertFalse(bad["all_windows_gigabit"])

    def test_invalid_windows_and_duration_never_turn_green(self):
        for seconds in [0,-1,math.nan,math.inf]:
            with self.assertRaises(ValueError): probe.summarize_windows([{"seconds":seconds,"bytes":100}])
            with self.assertRaises(ValueError): probe.checked_seconds(seconds)
        for value in ["nan","inf","901","-1"]:
            with self.assertRaises(ValueError): probe.checked_seconds(value)
        with self.assertRaises(ValueError): probe.summarize_windows([])
        with self.assertRaises(ValueError): probe.summarize_windows([{"seconds":1,"bytes":-1}])

    def test_proc_stat_handles_spaces_and_parentheses(self):
        fields=["0"]*40
        fields[0]="S"; fields[11]="12"; fields[12]="34"; fields[19]="99"; fields[21]="56"
        row=probe.proc_stat("123 (process (with) space) "+" ".join(fields))
        self.assertEqual(row,{"user":12,"system":34,"starttime":99,"rss_pages":56})

    def test_cpu_plan_never_fakes_independent_generator(self):
        with self.assertRaises(RuntimeError): hook.cpu_plan([0])
        self.assertIsNone(hook.cpu_plan([2,5])["generator"])
        self.assertEqual(hook.cpu_plan([2,5,7]),{"core":2,"edge":5,"generator":7})

    def test_exact_short_reads_and_eof(self):
        class Short:
            def __init__(self): self.data=[b"a",b"bc",b""]
            def recv(self,n): return self.data.pop(0)
        self.assertEqual(probe.exact(Short(),3),b"abc")
        with self.assertRaises(EOFError): probe.exact(Short(),4)

    def test_snapshot_real_process_or_explicit_proc_restriction(self):
        # Android PRoot may deny /proc; do not mislabel it as sampler evidence.
        try: snap=probe.snapshot([os.getpid()])
        except (PermissionError,FileNotFoundError): self.skipTest("sandbox /proc restriction")
        self.assertIn(str(os.getpid()),snap["processes"])
        self.assertTrue(snap["processes"][str(os.getpid())]["threads"])


class SocketTests(unittest.TestCase):
    def test_loopback_streamed_digest_and_complete_receiver_window(self):
        # Bounded <1s wall duration and <2 MiB data; exercises actual sockets.
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            with socket.socket() as reservation:
                reservation.bind(("127.0.0.1",0)); port=reservation.getsockname()[1]
            server=subprocess.Popen([sys.executable,probe.__file__,"receive","127.0.0.1",str(port),str(root/"receiver.json"),str(root/"ready")],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            try:
                deadline=time.monotonic()+5
                while not (root/"ready").exists():
                    if server.poll() is not None or time.monotonic()>deadline: self.fail("receiver startup")
                    time.sleep(.01)
                probe.send("127.0.0.1","127.0.0.1",port,.02,.12,8_000_000,str(root/"sender.json"))
                stdout,stderr=server.communicate(timeout=5)
                self.assertEqual(server.returncode,0,stderr.decode())
                receiver=json.loads((root/"receiver.json").read_text())
                sender=json.loads((root/"sender.json").read_text())
                self.assertTrue(receiver["complete"])
                self.assertEqual(receiver["sha256"],sender["sha256"])
                self.assertEqual(receiver["bytes"],sender["bytes"])
                self.assertEqual(len(receiver["receiver_windows"]),1)
            finally:
                if server.poll() is None: server.kill()
                server.communicate(timeout=5)

    def test_truncated_header_fails_instead_of_waiting_forever(self):
        a,b=socket.socketpair()
        with a,b:
            a.sendall(b"incomplete"); a.shutdown(socket.SHUT_WR)
            with self.assertRaises(EOFError): probe.exact(b,probe.HEADER.size)


if __name__ == "__main__": unittest.main()
