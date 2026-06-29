from frida_mcp.values import preview_of, is_pointer, pointer_address


def test_preview_uses_field_when_present():
    assert preview_of({"type": "number", "value": 42, "preview": "42"}) == "42"


def test_preview_derived_when_missing():
    assert preview_of({"type": "number", "value": 42}) == "42"
    assert preview_of({"type": "string", "value": "hi"}) == '"hi"'


def test_pointer_helpers():
    p = {"type": "pointer", "value": "0x140001000",
         "symbol": "a.exe!f", "preview": "0x140001000 a.exe!f"}
    assert is_pointer(p) is True
    assert pointer_address(p) == "0x140001000"
    n = {"type": "number", "value": 1, "preview": "1"}
    assert is_pointer(n) is False
    assert pointer_address(n) is None
