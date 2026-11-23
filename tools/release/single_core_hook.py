#!/usr/bin/env python3
"""C-tier fixture hook. Does not alter legacy smoke thresholds or packets."""
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import single_core_probe as probe


def run(command, **kwargs):
    return subprocess.run(command, check=True, **kwargs)


def cpu_plan(allowed):
    if len(allowed) < 2:
        raise RuntimeError("requires at least two allowed logical CPUs")
    return {"core": allowed[0], "edge": allowed[1],
            "generator": allowed[2] if len(allowed) >= 3 else None}


def main():
    stage, core_ns, edge_ns, work = sys.argv[1:]
    work = Path(work)
    if stage != "ready":
        return
    cpus = cpu_plan(sorted(os.sched_getaffinity(0)))
    out = Path(os.environ["BOREAS_CAPACITY_OUTPUT"]).resolve()
    out.mkdir(parents=True, exist_ok=True)
    binary = os.environ["BOREAS_CAPACITY_BINARY"]
    pids = [int((work / (role+".pid")).read_text()) for role in ["core", "edge"]]
    # Wait on actual production status, not merely TUN creation.
    deadline = time.monotonic() + 25
    while True:
        status = []
        for role in ["core","edge"]:
            result = run([binary,"ctl","status","--socket",str(work/(role+"-state")/"control.sock")],capture_output=True,text=True)
            status.append(json.loads(result.stdout))
        if all(row.get("daemon_connected") is True for row in status):
            break
        if time.monotonic() > deadline:
            raise TimeoutError("both authenticated endpoints not ready")
        time.sleep(.1)
    # Include all existing control/status threads in the endpoint's one-CPU
    # budget and keep rechecking: widening affinity is a hard diagnostic error.
    for role,pid in zip(["core","edge"],pids):
        for tid in os.listdir(f"/proc/{pid}/task"):
            os.sched_setaffinity(int(tid), {cpus[role]})
    (out/"plan.json").write_text(json.dumps({"cpu_plan":cpus,"claim":"diagnostic-not-single-vcpu-certification","softirq_isolation":"unproven","source_sha":os.environ.get("GITHUB_SHA")},sort_keys=True)+"\n")
    warm = float(os.environ.get("BOREAS_CAPACITY_WARM_SECONDS","2"))
    duration = probe.checked_seconds(os.environ.get("BOREAS_CAPACITY_SECONDS","5"))
    rate = int(os.environ.get("BOREAS_CAPACITY_RATE_BPS","0"))
    worker = str(Path(__file__).with_name("single_core_probe.py"))
    for colocation in ["separate", "colocated"]:
        if colocation == "separate" and cpus["generator"] is None:
            (out/"separate-unavailable.txt").write_text("fewer than three allowed CPUs; not fabricated from colocated results\n")
            continue
        for direct in [True,False]:
            for reverse in [False,True]:
                label=f"{colocation}-{'direct' if direct else 'overlay'}-{'core-to-edge' if reverse else 'edge-to-core'}"
                src_role,dst_role=("core","edge") if reverse else ("edge","core")
                src_ns,dst_ns=(core_ns,edge_ns) if reverse else (edge_ns,core_ns)
                address={"core": "192.0.2.1" if direct else "10.20.1.1", "edge": "192.0.2.2" if direct else "10.20.1.2"}
                port=18190
                ready=out/(label+".ready")
                ready.unlink(missing_ok=True)
                def command(namespace,role,args):
                    cpu=cpus["generator"] if colocation == "separate" else cpus[role]
                    return ["ip","netns","exec",namespace,"taskset","-c",str(cpu),"python3",worker]+args
                with (out/(label+".receiver.log")).open("w") as log:
                    receiver=subprocess.Popen(command(dst_ns,dst_role,["receive",address[dst_role],str(port),str(out/(label+".receiver.json")),str(ready)]),stdout=log,stderr=subprocess.STDOUT)
                    try:
                        deadline=time.monotonic()+10
                        while not ready.exists():
                            if receiver.poll() is not None or time.monotonic()>deadline:
                                raise RuntimeError("receiver did not bind")
                            time.sleep(.02)
                        (out/(label+".before.json")).write_text(json.dumps(probe.snapshot(pids),sort_keys=True)+"\n")
                        with (out/(label+".sender.log")).open("w") as sender_log:
                            sender=subprocess.Popen(command(src_ns,src_role,["send",address[src_role],address[dst_role],str(port),str(warm),str(duration),str(rate),str(out/(label+".sender.json"))]),stdout=sender_log,stderr=subprocess.STDOUT)
                            try:
                                deadline=time.monotonic()+warm+duration+35
                                samples=[]
                                while sender.poll() is None:
                                    if time.monotonic()>deadline: raise TimeoutError(label)
                                    state=probe.snapshot(pids)
                                    for role,pid in zip(["core","edge"],pids):
                                        expected=str(cpus[role])
                                        if any(t["affinity"]!=expected for t in state["processes"][str(pid)]["threads"].values()):
                                            raise AssertionError("endpoint thread escaped CPU budget")
                                    samples.append(state)
                                    if len(samples)>1024: raise RuntimeError("sampler bound")
                                    time.sleep(.25)
                                (out/(label+".samples.json")).write_text(json.dumps(samples,sort_keys=True)+"\n")
                                if sender.returncode: raise RuntimeError("sender failed: "+label)
                            finally:
                                if sender.poll() is None: sender.kill()
                                sender.wait()
                        if receiver.wait(timeout=10): raise RuntimeError("receiver failed: "+label)
                        (out/(label+".after.json")).write_text(json.dumps(probe.snapshot(pids),sort_keys=True)+"\n")
                        for role,ns in [("core",core_ns),("edge",edge_ns)]:
                            with (out/(label+"."+role+".tcp.txt")).open("w") as tcp:
                                run(["ip","netns","exec",ns,"ss","-tinm"],stdout=tcp)
                    finally:
                        if receiver.poll() is None: receiver.kill()
                        receiver.wait()
                print("single_core_capacity_completed="+label,flush=True)
    # Existing full-duplex smoke and its original acceptance still run next.

if __name__ == "__main__":
    main()
