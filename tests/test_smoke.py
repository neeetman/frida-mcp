import frida_mcp


def test_version_present():
    assert isinstance(frida_mcp.__version__, str)
    assert frida_mcp.__version__.count(".") == 2
