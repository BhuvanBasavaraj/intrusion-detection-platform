from backend.attack_stage import get_attack_stage


def test_failed_login_stage():
    event = {
        "event_type": "LOGIN",
        "status": "FAILED",
    }

    assert get_attack_stage(event) == "Initial Access Attempt"


def test_successful_login_stage():
    event = {
        "event_type": "LOGIN",
        "status": "SUCCESS",
    }

    assert get_attack_stage(event) == "Initial Access"


def test_privilege_escalation_stage():
    event = {
        "event_type": "PRIVILEGE_ESCALATION",
        "status": "SUCCESS",
    }

    assert get_attack_stage(event) == "Privilege Escalation"


def test_file_access_stage():
    event = {
        "event_type": "FILE_ACCESS",
        "status": "SUCCESS",
    }

    assert get_attack_stage(event) == "Data Access"


def test_unknown_event_stage():
    event = {
        "event_type": "UNKNOWN",
        "status": "SUCCESS",
    }

    assert get_attack_stage(event) == "Other Activity"