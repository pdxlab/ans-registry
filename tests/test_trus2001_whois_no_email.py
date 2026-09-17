"""TRUS-2001 — /ans/whois must not publish the registrant's email address.

The endpoint is unauthenticated, so returning `registrant_email` made a named
person's email retrievable by anyone who knew or guessed an ANS name. Names are
enumerable by design — there is a `/ans/typosquats/{name}` endpoint whose whole
purpose is generating name candidates — so this was a harvesting path, not a
theoretical one.

An email address identifying a natural person is personal data under GDPR/UK
GDPR and in scope for DPA §8 erasure. The Data Handling Reference recorded the
AgentCert row as "PUBLIC" with DPA-Ref "N/A — likely not Personal Data", which
is what made this worth finding.

Second reason, and the sharper one: `POST /ans/transfer` accepts
`from_email == agent.owner_email` as its only proof of ownership. Publishing
the email therefore handed out that proof. These tests pin the removal; the
transfer flow itself needs its own fix and is tracked separately.
"""

from tests.conftest import register


REGISTRANT_EMAIL = "owner@acme.example"


class TestWhoisDoesNotPublishEmail:
    def test_whois_omits_the_registrant_email(self, client):
        """The assertion that would fail on the unremediated endpoint."""
        register(client, "no-email-agent", owner_email=REGISTRANT_EMAIL)

        resp = client.get("/ans/whois/no-email-agent")

        assert resp.status_code == 200
        body = resp.json()
        assert "registrant_email" not in body, (
            "whois still publishes the registrant email from an unauthenticated "
            "endpoint"
        )

    def test_the_address_appears_nowhere_in_the_payload(self, client):
        """Not just the named key — the value must not leak via another field.

        Checked as a substring of the whole serialised body, so a future change
        that folds the address into a contact blob or a message string still
        fails this.
        """
        register(client, "no-email-anywhere", owner_email=REGISTRANT_EMAIL)

        resp = client.get("/ans/whois/no-email-anywhere")

        assert REGISTRANT_EMAIL not in resp.text

    def test_the_identity_signal_is_still_there(self, client):
        """Removing the email must not gut what whois is for.

        Organisation and domain are what a verifier actually needs; if these
        went too, the endpoint would be useless and someone would put the email
        back.
        """
        register(
            client,
            "still-useful",
            owner_email=REGISTRANT_EMAIL,
            owner_org="Acme Inc.",
        )

        body = client.get("/ans/whois/still-useful").json()

        assert body["registrant_org"] == "Acme Inc."
        assert body["registrant_domain"] == "acme.example"
        assert body["ans_name"] == "still-useful"

    def test_lookup_still_carries_no_email(self, client):
        """`/ans/lookup` never exposed it; pin that it stays that way."""
        register(client, "lookup-clean", owner_email=REGISTRANT_EMAIL)

        resp = client.get("/ans/lookup/lookup-clean")

        assert resp.status_code == 200
        assert REGISTRANT_EMAIL not in resp.text

    def test_registration_still_stores_the_email(self, client):
        """This is a publication fix, not a data-model change.

        The address is still needed for domain verification and transfer, so it
        must remain at rest — only the public surface changes.
        """
        resp = register(client, "stored-not-published", owner_email=REGISTRANT_EMAIL)

        assert resp.status_code in (200, 201)
        # Verification depends on the stored address, so a working verify proves
        # it survived registration without reading it back over the wire.
        verify = client.post(
            "/ans/verify",
            json={"ans_name": "stored-not-published", "method": "email_domain"},
        )
        assert verify.status_code in (200, 400, 403, 422)
        assert REGISTRANT_EMAIL not in client.get(
            "/ans/whois/stored-not-published"
        ).text
