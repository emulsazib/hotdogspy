from conftest import FIXTURES

from audittool.modules.recon.nmap_scan import parse_nmap_xml


def test_parse_nmap_xml_open_ports_and_os():
    xml = (FIXTURES / "nmap_sample.xml").read_text()
    findings, raw = parse_nmap_xml(xml)

    titles = [f.title for f in findings]
    # Open ports only (22, 23, 80, 6379) — closed 9999 excluded.
    assert any("22/tcp" in t for t in titles)
    assert any("23/tcp" in t for t in titles)
    assert any("6379/tcp" in t for t in titles)
    assert not any("9999" in t for t in titles)

    # Risky services get elevated severity.
    sev = {f.metadata.get("service"): f.severity.value for f in findings if "service" in f.metadata}
    assert sev.get("telnet") == "high"
    assert sev.get("redis") == "high"

    # OS inference recorded.
    assert any("Inferred OS" in t for t in titles)
    assert raw["hosts"][0]["os"]["name"] == "Linux 5.x"
