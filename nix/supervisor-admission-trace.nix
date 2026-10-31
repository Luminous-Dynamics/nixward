{ identities }:
vector:
let
  snapshot = vector.snapshot;
  slots = [
    snapshot.replay_consumption
    snapshot.verified_permit
    snapshot.attempt_reservation
    snapshot.journal_entry
  ];
  resolve = key:
    if builtins.isString key && builtins.hasAttr key identities
    then identities.${key}
    else null;
  resolved = map resolve slots;
  present = builtins.filter (record: record != null) resolved;
  hasUnknownReference = builtins.any
    (key: key != null && resolve key == null)
    slots;
  validToken = value:
    builtins.isString value
    && builtins.stringLength value > 0
    && builtins.stringLength value <= 256
    && builtins.match "[^[:space:][:cntrl:]]+" value != null;
  validDigest = value:
    builtins.isString value
    && builtins.match "[0-9a-f]{64}" value != null;
  validIdentity = identity:
    builtins.isAttrs identity
    && validToken identity.transaction_id
    && validToken identity.attempt_id
    && validDigest identity.replay_key
    && validDigest identity.plan_digest
    && validDigest identity.machine_binding_digest
    && validDigest identity.permit_digest
    && validDigest identity.commit_id;
  validIntent =
    validToken vector.intent.transaction_id
    && validDigest vector.intent.replay_key
    && validDigest vector.intent.plan_digest
    && validDigest vector.intent.machine_binding_digest;
  proofFields = [
    "signature_valid"
    "trusted_signer"
    "exact_audience"
    "exact_subject"
    "exact_machine_binding"
    "exact_plan_binding"
    "fresh"
  ];
  proofSatisfied = builtins.all
    (field: (vector.proof.${field} or false) == true)
    proofFields;
  snapshotShapeValid = builtins.isBool snapshot.unresolved_attempt;
  snapshotClass =
    if !snapshotShapeValid || hasUnknownReference then "inconsistent"
    else if present == [] && !snapshot.unresolved_attempt then "empty"
    else if builtins.length present == 4
      && builtins.all (record: record == builtins.head present) (builtins.tail present)
      && validIdentity (builtins.head present)
    then "complete"
    else "inconsistent";
  decideComplete = identity:
    if identity.replay_key == vector.intent.replay_key then
      if identity.transaction_id == vector.intent.transaction_id
        && identity.plan_digest == vector.intent.plan_digest
        && identity.machine_binding_digest == vector.intent.machine_binding_digest
      then "resume_existing_attempt"
      else "reject_replay_conflict"
    else if identity.transaction_id == vector.intent.transaction_id then
      if snapshot.unresolved_attempt
      then "hold_unresolved_attempt"
      else "commit_admission_atomically"
    else "hold_inconsistent_persistence";
in
  if !validIntent then "reject_invalid_intent"
  else if !proofSatisfied then "reject_invalid_proof"
  else if snapshotClass == "empty" then "commit_admission_atomically"
  else if snapshotClass == "inconsistent" then "hold_inconsistent_persistence"
  else decideComplete (builtins.head present)