from app.domain.ioc.types import IocType
from app.services.playbooks import playbook_for


def test_hash_playbook_includes_static_triage_steps() -> None:
    playbooks = playbook_for(IocType.SHA256, "high")

    assert len(playbooks) >= 2
    triage = next(p for p in playbooks if p["title"] == "Static malware triage (PE)")
    assert triage["source"] == "Anthropic Cybersecurity Skills"
    assert triage["reference"].startswith("https://github.com/mukul975/")
    assert triage["reference"].endswith(
        "performing-static-malware-analysis-with-pe-studio/SKILL.md"
    )
    assert len(triage["steps"]) >= 5
    titles = [step["title"] for step in triage["steps"]]
    assert "Extract strings and indicators" in titles
    assert "Detonate in a sandbox" in titles
    assert all(step["title"] and step["detail"] for step in triage["steps"])


def test_high_risk_adds_escalation_playbook() -> None:
    playbooks = playbook_for(IocType.URL, "critical")

    escalation = next(p for p in playbooks if p["title"] == "High-risk escalation")
    assert [step["title"] for step in escalation["steps"]] == ["Contain", "Notify", "Document"]


def test_medium_risk_has_no_escalation() -> None:
    titles = [p["title"] for p in playbook_for(IocType.EMAIL, "medium")]

    assert "High-risk escalation" not in titles
    assert "Business Email Compromise check" in titles


def test_every_playbook_has_full_contract() -> None:
    for ioc_type in list(IocType):
        for severity in ("unknown", "low", "medium", "high", "critical"):
            for playbook in playbook_for(ioc_type, severity):
                assert playbook["title"]
                assert playbook["summary"]
                assert playbook["source"] == "Anthropic Cybersecurity Skills"
                assert playbook["reference"].startswith("https://github.com/mukul975/")
                assert playbook["steps"], f"{ioc_type}/{severity} playbook has no steps"
                for step in playbook["steps"]:
                    assert step["title"]
                    assert step["detail"]
                    assert isinstance(step["tool"], str)
