#!/usr/bin/env python3
import json,sys
x=json.load(open(sys.argv[1])); assert x['schema_version']==1; assert x['source_kind']=='deterministic-synthetic-or-owner-reviewed-v45'; assert x['payload_capture'] is False
assert x['baseline'] and x['calibration'] and x['held_out']; ci={c['case_id'] for c in x['calibration']}; hi={c['case_id'] for c in x['held_out']}; assert ci.isdisjoint(hi)
for part in ['calibration','held_out']:
    labels={c['label'] for c in x[part]}; assert {'in-distribution','benign-novel','synthetic-anomaly'} <= labels
for o in x['baseline']+[c['observation'] for p in ['calibration','held_out'] for c in x[p]]: assert o['payload_bytes_captured']==0
print('V45 corpus: disjoint calibration/held-out partitions, semantic classes present, payload-free')
