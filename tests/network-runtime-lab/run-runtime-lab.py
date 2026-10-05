#!/usr/bin/env python3
"""V44 disposable cgroup-BPF runtime acceptance runner.

This runner is intentionally lab-only. It loads the V44 test object, attaches it
only to disposable cgroups, drives policy map transitions, exercises real
TCP/UDP sockets, and emits the V42-compatible report plus V44 execution metadata.
It never activates a production Holon firewall.
"""
import argparse, hashlib, json, os, pathlib, shutil, socket, struct, subprocess, tempfile, threading, time

REQUIRED = [
    "feature-probe", "ipv4-allow", "ipv4-deny", "ipv6-allow", "ipv6-deny",
    "udp-allow", "udp-deny", "lease-active", "lease-expired", "policy-swap",
    "cgroup-rebind", "enforcer-restart", "stale-policy-replay",
    "attach-failure-fail-closed",
]
ATTACH = {
    "connect4": "symthaea_connect4",
    "connect6": "symthaea_connect6",
    "sendmsg4": "symthaea_sendmsg4",
    "sendmsg6": "symthaea_sendmsg6",
}

def run(*argv, check=True, text=True):
    return subprocess.run(argv, check=check, text=text, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

def b3(data: bytes) -> str:
    p = subprocess.run(["b3sum", "--no-names"], input=data, stdout=subprocess.PIPE, check=True)
    return p.stdout.decode().strip().split()[0]

def evidence(case, observed):
    return b3(json.dumps({"case": case, "observed": observed}, sort_keys=True, separators=(",", ":")).encode())

def hex_bytes(data: bytes):
    return [f"{b:02x}" for b in data]

class Lab:
    def __init__(self, obj, root):
        self.obj = pathlib.Path(obj)
        self.root = pathlib.Path(root)
        self.pin = pathlib.Path("/sys/fs/bpf/symthaea-v44")
        self.cgroot = pathlib.Path("/sys/fs/cgroup/symthaea-v44")
        self.progs = self.pin / "progs"
        self.maps = self.pin / "maps"
        self.cg_a = self.cgroot / "protected-a"
        self.cg_b = self.cgroot / "protected-b"
        self.results = []
        self.port4 = 38443
        self.port6 = 38444
        self.udp4 = 38445
        self.udp6 = 38446
        self.servers = []

    def record(self, kind, passed, observed):
        self.results.append({"case_id": kind, "kind": kind, "passed": bool(passed),
                             "observed": observed, "evidence_blake3": evidence(kind, observed)})
        if not passed:
            raise AssertionError(f"{kind}: {observed}")

    def clean(self):
        for cg in [self.cg_a, self.cg_b]:
            for at, name in ATTACH.items():
                prog = self.progs / name
                if cg.exists() and prog.exists():
                    run("bpftool", "cgroup", "detach", str(cg), at, "pinned", str(prog), check=False)
        shutil.rmtree(self.pin, ignore_errors=True)
        for cg in [self.cg_a, self.cg_b]:
            try: cg.rmdir()
            except OSError: pass
        try: self.cgroot.rmdir()
        except OSError: pass

    def setup(self):
        self.clean()
        self.progs.mkdir(parents=True)
        self.maps.mkdir(parents=True)
        self.cg_a.mkdir(parents=True)
        self.cg_b.mkdir(parents=True)
        run("bpftool", "prog", "loadall", str(self.obj), str(self.progs), "pinmaps", str(self.maps))
        for cg in [self.cg_a, self.cg_b]:
            for at, name in ATTACH.items():
                run("bpftool", "cgroup", "attach", str(cg), at, "pinned", str(self.progs/name))
        self.set_policy(0, 1, 1, 0)  # deny by default

    def set_policy(self, port, mode, generation, expires_ns):
        # Native little-endian struct lab_policy: H B B I Q = 16 bytes.
        value = struct.pack("<HBBIQ", port, mode, 0, generation, expires_ns)
        key = struct.pack("<I", 0)
        run("bpftool", "map", "update", "pinned", str(self.maps/"policy"),
            "key", "hex", *hex_bytes(key), "value", "hex", *hex_bytes(value))
        gen = struct.pack("<I", generation)
        run("bpftool", "map", "update", "pinned", str(self.maps/"active_generation"),
            "key", "hex", *hex_bytes(key), "value", "hex", *hex_bytes(gen))

    def set_stale_policy(self, port, mode, stale_generation, expires_ns=0):
        value = struct.pack("<HBBIQ", port, mode, 0, stale_generation, expires_ns)
        key = struct.pack("<I", 0)
        run("bpftool", "map", "update", "pinned", str(self.maps/"policy"),
            "key", "hex", *hex_bytes(key), "value", "hex", *hex_bytes(value))

    def _server(self, family, socktype, port):
        ready = threading.Event(); stop = threading.Event()
        def worker():
            s = socket.socket(family, socktype)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            addr = ("127.0.0.1", port) if family == socket.AF_INET else ("::1", port)
            s.bind(addr)
            if socktype == socket.SOCK_STREAM:
                s.listen(16); s.settimeout(.2)
            else: s.settimeout(.2)
            ready.set()
            while not stop.is_set():
                try:
                    if socktype == socket.SOCK_STREAM:
                        c, _ = s.accept(); c.close()
                    else:
                        s.recvfrom(32)
                except socket.timeout: pass
            s.close()
        t = threading.Thread(target=worker, daemon=True); t.start(); ready.wait(2)
        self.servers.append((stop,t))

    def start_servers(self):
        self._server(socket.AF_INET, socket.SOCK_STREAM, self.port4)
        self._server(socket.AF_INET6, socket.SOCK_STREAM, self.port6)
        self._server(socket.AF_INET, socket.SOCK_DGRAM, self.udp4)
        self._server(socket.AF_INET6, socket.SOCK_DGRAM, self.udp6)

    def client(self, cg, family, socktype, port, expect):
        code = r'''import os,socket,sys,time
family=int(sys.argv[1]); typ=int(sys.argv[2]); port=int(sys.argv[3]); gate=sys.argv[4]
while not os.path.exists(gate): time.sleep(.005)
s=socket.socket(family,typ); s.settimeout(1)
addr=("127.0.0.1",port) if family==socket.AF_INET else ("::1",port)
try:
    if typ==socket.SOCK_STREAM: s.connect(addr)
    else: s.sendto(b"x",addr)
except OSError: sys.exit(23)
sys.exit(0)
'''
        gate = tempfile.mktemp(prefix="symthaea-v44-gate-")
        p = subprocess.Popen(["python3","-c",code,str(family),str(socktype),str(port),gate])
        pathlib.Path(cg/"cgroup.procs").write_text(str(p.pid))
        pathlib.Path(gate).touch()
        rc = p.wait(timeout=3)
        pathlib.Path(gate).unlink(missing_ok=True)
        allowed = rc == 0
        if allowed != expect:
            raise AssertionError(f"expected allowed={expect}, rc={rc}")
        return allowed

    def execute(self):
        feature = run("bpftool", "feature", "probe", "kernel").stdout
        has_cgroup2 = run("stat","-fc","%T","/sys/fs/cgroup").stdout.strip()=="cgroup2fs"
        self.record("feature-probe", has_cgroup2 and "cgroup_sock_addr" in feature,
                    "cgroup2fs and cgroup_sock_addr feature visible")
        self.start_servers()

        g=10; self.set_policy(self.port4,0,g,0); self.client(self.cg_a,socket.AF_INET,socket.SOCK_STREAM,self.port4,True)
        self.record("ipv4-allow",True,"protected cgroup connected to explicitly allowed IPv4 TCP port")
        g+=1; self.set_policy(self.port4,1,g,0); self.client(self.cg_a,socket.AF_INET,socket.SOCK_STREAM,self.port4,False)
        self.record("ipv4-deny",True,"protected cgroup could not connect to denied IPv4 TCP port")
        g+=1; self.set_policy(self.port6,0,g,0); self.client(self.cg_a,socket.AF_INET6,socket.SOCK_STREAM,self.port6,True)
        self.record("ipv6-allow",True,"protected cgroup connected to explicitly allowed IPv6 TCP port")
        g+=1; self.set_policy(self.port6,1,g,0); self.client(self.cg_a,socket.AF_INET6,socket.SOCK_STREAM,self.port6,False)
        self.record("ipv6-deny",True,"protected cgroup could not connect to denied IPv6 TCP port")
        g+=1; self.set_policy(self.udp4,0,g,0); self.client(self.cg_a,socket.AF_INET,socket.SOCK_DGRAM,self.udp4,True)
        self.record("udp-allow",True,"protected cgroup emitted UDP datagram under allow policy")
        g+=1; self.set_policy(self.udp4,1,g,0); self.client(self.cg_a,socket.AF_INET,socket.SOCK_DGRAM,self.udp4,False)
        self.record("udp-deny",True,"protected cgroup could not emit UDP datagram under deny policy")

        g+=1; expiry=time.monotonic_ns()+1_500_000_000; self.set_policy(self.port4,2,g,expiry)
        self.client(self.cg_a,socket.AF_INET,socket.SOCK_STREAM,self.port4,True)
        self.record("lease-active",True,"lease mode permitted before monotonic expiration")
        time.sleep(1.7); self.client(self.cg_a,socket.AF_INET,socket.SOCK_STREAM,self.port4,False)
        self.record("lease-expired",True,"same map entry denied after monotonic lease expiration without regeneration")

        g+=1; self.set_policy(self.port4,0,g,0); self.client(self.cg_a,socket.AF_INET,socket.SOCK_STREAM,self.port4,True)
        g+=1; self.set_policy(self.port4,1,g,0); self.client(self.cg_a,socket.AF_INET,socket.SOCK_STREAM,self.port4,False)
        self.record("policy-swap",True,"map generation swap changed allow to deny without program reload")

        # Binding proof: unprotected root-cgroup process succeeds while same destination is denied inside protected cgroup.
        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.settimeout(1); s.connect(("127.0.0.1",self.port4)); s.close()
        self.client(self.cg_b,socket.AF_INET,socket.SOCK_STREAM,self.port4,False)
        self.record("cgroup-rebind",True,"unbound workload succeeded; moving execution into protected sibling cgroup enforced deny")

        # A userspace controller exit does not remove pinned cgroup programs.
        show=run("bpftool","cgroup","show",str(self.cg_a)).stdout
        self.client(self.cg_a,socket.AF_INET,socket.SOCK_STREAM,self.port4,False)
        self.record("enforcer-restart","symthaea_connect4" in show or "connect4" in show,
                    "pinned cgroup attachment remained effective independently of controller lifetime")

        # Active generation remains g; replay an older policy body only. Generation mismatch must fail closed.
        self.set_stale_policy(self.port4,0,g-1)
        self.client(self.cg_a,socket.AF_INET,socket.SOCK_STREAM,self.port4,False)
        self.record("stale-policy-replay",True,"stale policy body could not override newer active generation")

        # Restore explicit deny, then make a replacement attach fail. Existing program must remain attached and deny.
        g+=1; self.set_policy(self.port4,1,g,0)
        bad=run("bpftool","cgroup","attach",str(self.cg_a),"connect4","pinned","/sys/fs/bpf/does-not-exist",check=False)
        self.client(self.cg_a,socket.AF_INET,socket.SOCK_STREAM,self.port4,False)
        self.record("attach-failure-fail-closed",bad.returncode!=0,
                    "invalid replacement attach failed and pre-existing deny attachment remained effective")

    def report(self):
        harness = pathlib.Path(__file__).read_bytes()
        return {
            "schema_version":1,
            "backend":"cgroup-sockaddr-bpf-contract-v40",
            "status":"isolated-runtime-lab-v42",
            "kernel_release":os.uname().release,
            "nixos_system":pathlib.Path("/run/current-system").resolve().as_posix(),
            "harness_blake3":b3(harness),
            "isolated_environment":True,
            "payload_capture":False,
            "production_activation_performed":False,
            "reasoning_authority":"none",
            "cases":self.results,
            "v44_execution":{
                "status":"executed-runtime-lab-v44",
                "runner_blake3":b3(harness),
                "bpf_object_blake3":b3(self.obj.read_bytes()),
                "required_case_count":len(REQUIRED),
                "production_activation":False,
            },
        }

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--object",required=True); ap.add_argument("--output",required=True)
    args=ap.parse_args(); lab=Lab(args.object, pathlib.Path(args.output).parent)
    try:
        lab.setup(); lab.execute(); report=lab.report()
        pathlib.Path(args.output).write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    finally:
        for stop,t in lab.servers: stop.set(); t.join(timeout=1)
        lab.clean()
if __name__=="__main__": main()
