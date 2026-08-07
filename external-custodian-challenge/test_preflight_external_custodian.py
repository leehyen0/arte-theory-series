import preflight_external_custodian as p

def local(kind,row): return p.split(p.VALIDATORS[kind](row))

def test_registration_example(): assert local("registration",p.example("registration"))[0]==[]

def test_registration_wrong_freeze():
    r=p.example("registration"); r["protocol_freeze_hash"]="0"*64
    assert "PROTOCOL_FREEZE_MISMATCH" in local("registration",r)[0]

def test_evidence_example(): assert local("evidence",p.example("evidence"))[0]==[]

def test_evidence_missing_kind():
    r=p.example("evidence"); r["evidence"]=r["evidence"][:2]
    assert "MISSING_EVIDENCE_KIND:evaluation_independence" in local("evidence",r)[0]

def test_evidence_duplicate_hash():
    r=p.example("evidence"); r["evidence"][1]["artifact_sha256"]=r["evidence"][0]["artifact_sha256"]
    assert "DUPLICATE_EVIDENCE_SHA256_WITHIN_BUNDLE" in local("evidence",r)[0]

def test_review_example(): assert local("review",p.example("review"))[0]==[]

def test_independence_review_requires_shared_control_attestation():
    r=p.example("review"); r["review_type"]="independence"; r["attests_no_shared_control_for_evaluation"]=False
    assert "TRUE_REQUIRED:attests_no_shared_control_for_evaluation" in local("review",r)[0]

def test_review_bad_hash():
    r=p.example("review"); r["evidence_bundle_hash"]="bad"
    assert "INVALID_SHA256:evidence_bundle_hash" in local("review",r)[0]

def test_event_example(): assert local("event",p.example("event"))[0]==[]

def test_event_wrong_freeze():
    r=p.example("event"); r["protocol_freeze_hash"]=p.QUORUM_FREEZE
    assert "EVENT_PROTOCOL_FREEZE_MISMATCH" in local("event",r)[0]

def test_event_private_nonce():
    r=p.example("event"); r["nonce"]="x"
    problems,_=local("event",r)
    assert any(x.startswith("PRIVATE_MATERIAL_FORBIDDEN:") for x in problems)

def test_server_checks_do_not_count_as_local_failure():
    localp,server=p.split(p.validate_registration(p.example("registration")))
    assert localp==[] and server

def test_local_pass_never_grants_server_authority():
    problems=p.validate_evidence_bundle(p.example("evidence"))
    assert "SERVER_CHECK_REQUIRED:SUBJECT_MUST_HAVE_ACCEPTED_REGISTRATION" in problems
