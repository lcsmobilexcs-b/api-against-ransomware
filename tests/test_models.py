from ss_bt_automation.models import (
    parse_ai_analysis_field,
    parse_executing_username,
)


def test_parse_executing_username_domain_slash() -> None:
    u, d = parse_executing_username("HOST\\Administrator")
    assert u == "Administrator"
    assert d == "HOST"


def test_parse_executing_username_upn() -> None:
    u, d = parse_executing_username("jane.doe@corp.local")
    assert u == "jane.doe"
    assert d == "corp.local"


def test_parse_ai_analysis() -> None:
    p = parse_ai_analysis_field('{"summary":"x","severity":95}')
    assert p.severity == 95
    assert p.summary == "x"
