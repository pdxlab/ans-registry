"""TRUS-2286: a matching email domain no longer earns DV.

``/ans/register`` stores a caller-supplied ``owner_email`` and ``owner_domain``,
and ``/ans/verify`` is unauthenticated, so email-DV let anyone claim a domain
they don't control. Only a DNS TXT record under the claimed domain proves it.
All names and domains are synthetic.
"""

from unittest.mock import patch

from sqlmodel import select

from app.models import Agent
from tests.conftest import register


def _agent(session, ans_name):
    session.expire_all()
    return session.exec(select(Agent).where(Agent.ans_name == ans_name)).one()


def test_a_matching_email_domain_no_longer_verifies(client, session):
    """
    Scenario: the registrant's email domain matches the claimed domain.
    Steps: register ai@acme-2286.example; verify with method=email.
    Expected: 200, status email_not_accepted, the exact TXT record to publish;
    the agent stays unverified.
    """
    register(client, "acme-2286-agent", owner_email="ai@acme-2286.example")
    token = _agent(session, "acme-2286-agent").verification_token

    resp = client.post("/ans/verify", json={"ans_name": "acme-2286-agent", "method": "email"})

    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "email_not_accepted"
    assert body["record"] == f'_ans-verify.acme-2286.example  TXT  "{token}"'
    agent = _agent(session, "acme-2286-agent")
    assert (agent.verified, agent.assurance_tier) == (False, "unverified")


def test_claiming_someone_elses_domain_by_email_earns_nothing(client, session):
    """The ticket's spoof: register x@victim, claim victim, "verify"."""
    register(
        client, "spoofed-2286-agent",
        owner_email="anyone@victim-2286.example", owner_domain="victim-2286.example",
    )
    client.post("/ans/verify", json={"ans_name": "spoofed-2286-agent", "method": "email"})
    assert _agent(session, "spoofed-2286-agent").assurance_tier == "unverified"


def test_the_default_method_is_the_dns_check(client, session):
    register(client, "default-2286-agent", owner_email="ai@acme-2286.example")
    token = _agent(session, "default-2286-agent").verification_token

    with patch("app.main.check_dns_txt", return_value=False) as dns:
        resp = client.post("/ans/verify", json={"ans_name": "default-2286-agent"})

    dns.assert_called_once_with("acme-2286.example", token)
    assert resp.json()["status"] == "dns_not_found"
    assert _agent(session, "default-2286-agent").verified is False


def test_a_dns_record_still_earns_dv(client, session):
    register(client, "dns-2286-agent", owner_email="ai@acme-2286.example")
    with patch("app.main.check_dns_txt", return_value=True):
        resp = client.post("/ans/verify", json={"ans_name": "dns-2286-agent", "method": "dns_txt"})
    assert resp.json()["assurance_tier"] == "DV"
    assert _agent(session, "dns-2286-agent").verification_method == "dns_txt"


def test_an_agent_verified_by_email_before_keeps_its_tier(client, session):
    """Downgrading earlier email-DV names is a separate decision; this change
    must not do it as a side effect."""
    register(client, "legacy-2286-agent", owner_email="ai@acme-2286.example")
    agent = _agent(session, "legacy-2286-agent")
    agent.verified, agent.verification_method, agent.assurance_tier = True, "email", "DV"
    session.add(agent)
    session.commit()

    resp = client.post("/ans/verify", json={"ans_name": "legacy-2286-agent", "method": "email"})

    assert resp.json()["status"] == "already_verified"
    assert _agent(session, "legacy-2286-agent").assurance_tier == "DV"
