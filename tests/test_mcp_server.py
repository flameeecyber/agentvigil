import io
import json

from vigil import mcp_server


def _rpc(messages):
    stdin = io.StringIO("\n".join(json.dumps(m) for m in messages) + "\n")
    stdout = io.StringIO()
    mcp_server.serve(stdin, stdout)
    return [json.loads(line) for line in stdout.getvalue().splitlines()]


def test_initialize_and_tools_list():
    out = _rpc(
        [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        ]
    )
    assert out[0]["result"]["serverInfo"]["name"] == "agentvigil"
    assert out[0]["result"]["protocolVersion"]
    names = {tool["name"] for tool in out[1]["result"]["tools"]}
    assert {"scan_surface", "capability_report", "verify_lock", "list_rules"} <= names
    for tool in out[1]["result"]["tools"]:
        assert tool["inputSchema"]["type"] == "object"


def test_scan_tool_finds_the_evil_fixture():
    out = _rpc(
        [
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "scan_surface", "arguments": {"path": "examples/evil-repo"}},
            }
        ]
    )
    payload = json.loads(out[0]["result"]["content"][0]["text"])
    assert payload["trust"]["score"] < 50
    assert any(f["rule_id"] == "AV-EXEC-001" for f in payload["findings"])
    assert "exec.shell" in payload["capabilities"]


def test_capability_report_returns_counts():
    out = _rpc(
        [
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {"name": "capability_report", "arguments": {"path": "examples/evil-repo"}},
            }
        ]
    )
    payload = json.loads(out[0]["result"]["content"][0]["text"])
    assert payload["counts"]["critical"] >= 1
    assert payload["capabilities"]


def test_unknown_method_and_tool_return_errors_without_crashing():
    out = _rpc(
        [
            {"jsonrpc": "2.0", "id": 5, "method": "nope"},
            {
                "jsonrpc": "2.0",
                "id": 6,
                "method": "tools/call",
                "params": {"name": "nope", "arguments": {}},
            },
        ]
    )
    assert out[0]["error"]["code"] == -32601
    assert out[1]["result"]["isError"] is True


def test_parse_error_is_reported_not_raised():
    stdin = io.StringIO("{not json\n")
    stdout = io.StringIO()
    assert mcp_server.serve(stdin, stdout) == 0
    assert json.loads(stdout.getvalue())["error"]["code"] == -32700
