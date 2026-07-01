from conftest import FIXTURES

from audittool.core.orchestrator import Orchestrator
from audittool.core.scope import Scope
from audittool.core.schema import ScanReport


def test_orchestrator_offline_recon_and_report():
    # Attested loopback scope so the scope-gated recon module runs.
    scope = Scope(attested=True, domains=[], networks=["127.0.0.1"])
    orch = Orchestrator(scope=scope)

    report = orch.run(
        target="127.0.0.1",
        modules=["recon"],
        options={"nmap_xml": str(FIXTURES / "nmap_sample.xml")},
    )

    assert isinstance(report, ScanReport)
    assert report.scope_authorized is True
    assert report.finished_at is not None
    # Recon produced findings from the fixture.
    assert len(report.all_findings) > 0
    # Module D produced a remediation section (offline stub with no keys).
    assert report.remediation is not None
    assert len(report.remediation.prioritized_steps) > 0
    # Report round-trips through JSON.
    dumped = report.model_dump_json()
    assert ScanReport.model_validate_json(dumped).id == report.id


def test_scope_gated_module_skips_when_unauthorized():
    scope = Scope(attested=False, domains=[], networks=[])
    orch = Orchestrator(scope=scope)
    report = orch.run(
        target="example.com",
        modules=["recon"],
        confirm=lambda t, i: False,  # decline authorization
        options={"nmap_xml": str(FIXTURES / "nmap_sample.xml")},
        with_remediation=False,
    )
    recon = [m for m in report.modules if m.name == "recon"][0]
    assert recon.status.value == "skipped"


def test_packet_module_offline_leak_detection():
    scope = Scope(attested=True, domains=[], networks=["127.0.0.1"])
    orch = Orchestrator(scope=scope)
    report = orch.run(
        target="127.0.0.1",
        modules=["packet"],
        options={"pcap": "data/samples/sample.pcap"},
        with_remediation=False,
    )
    titles = [f.title for f in report.all_findings]
    assert any("data leak" in t.lower() or "cleartext" in t.lower() for t in titles)
