#!/usr/bin/env python3
"""Generate deterministic metadata-only V45 calibration fixtures.
The generator creates disjoint calibration and held-out semantic scenarios. It
does not pick a novelty threshold and never emits payload bytes.
"""
import argparse, hashlib, json, random
H=lambda s: hashlib.sha256(s.encode()).hexdigest()
def obs(case,zone,proto,sent,recv,dur,hour,decision="allowed",cap=True):
    return {"schema_version":1,"holon_id":"lab-holon","network_policy_blake3":H("policy"),"workload_blake3":H("browser-workload"),"capability_blake3":H("web-cap") if cap else None,"decision":decision,"direction":"outbound","protocol":proto,"destination_zone":zone,"destination_identity_blake3":H("dest:"+case),"bytes_sent":sent,"bytes_received":recv,"duration_ms":dur,"hour_bucket":hour,"payload_bytes_captured":0}
def case(i,label,kind,base): return {"case_id":f"{kind}-{i:03d}","label":label,"observation":base}
def build(seed=451):
    r=random.Random(seed)
    baseline=[]
    for i in range(24): baseline.append(obs(f"normal-{i%4}","internet","tcp",r.randint(600,4000),r.randint(20_000,180_000),r.randint(80,900),8+i%10))
    def partition(prefix):
        out=[]
        for i in range(8): out.append(case(i,"in-distribution",prefix+"-normal",obs(f"normal-{i%4}","internet","tcp",1200+i*50,60_000+i*2000,200+i*10,9+i%8)))
        for i in range(8): out.append(case(i,"benign-novel",prefix+"-benign",obs(f"benign-{i}","internet","tcp",80_000+i*7000,8_000_000+i*200_000,30_000+i*1000,12+i%5)))
        for i in range(8): out.append(case(i,"synthetic-anomaly",prefix+"-anomaly",obs(f"beacon-{i}","unknown","udp",120+i,10+i,45_000+i*3000,2+i%4)))
        for i in range(4): out.append(case(i,"policy-contradiction",prefix+"-policy",obs(f"denied-{i}","unknown","tcp",50,0,10,3,decision="no-matching-capability",cap=False)))
        return out
    return {"schema_version":1,"experiment_id":f"v45-deterministic-{seed}","source_kind":"deterministic-synthetic-or-owner-reviewed-v45","payload_capture":False,"baseline":baseline,"calibration":partition("cal"),"held_out":partition("hold")}
if __name__=='__main__':
    ap=argparse.ArgumentParser(); ap.add_argument('--output',required=True); ap.add_argument('--seed',type=int,default=451); a=ap.parse_args(); open(a.output,'w').write(json.dumps(build(a.seed),indent=2,sort_keys=True)+'\n')
