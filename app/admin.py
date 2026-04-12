"""
ANS Admin Dashboard — served at /admin
Standalone HTML admin for the Agent Naming Service.

Shows:
1. Registry overview (total agents, verified, transfers, scores)
2. All registered agents (add/edit/remove)
3. Verification status
4. Ownership transfers
5. Public TrustScore rankings (agents, chrome extensions, COTS)
6. GTM outreach tracking
"""

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlmodel import Session, select, func
from .database import get_session
from .models import Agent, Transfer, LookupLog
from .auth import get_current_admin, AdminUser, SESSION_COOKIE

router = APIRouter()


def admin_html(content: str, active_tab: str = "overview") -> str:
    """Wrap content in admin layout."""

    tabs = [
        ("overview", "Overview", "/admin"),
        ("agents", "Agents", "/admin/agents"),
        ("transfers", "Transfers", "/admin/transfers"),
        ("rankings", "Public Rankings", "/admin/rankings"),
        ("outreach", "GTM Outreach", "/admin/outreach"),
        ("users", "Admin Users", "/admin/users"),
    ]

    tab_html = ""
    for key, label, href in tabs:
        active = "background:#0891b2;color:white;" if key == active_tab else "color:#64748b;"
        tab_html += f'<a href="{href}" style="padding:8px 16px;border-radius:6px;font-size:13px;font-weight:600;text-decoration:none;{active}">{label}</a>'

    return f"""<!DOCTYPE html>
<html>
<head>
<title>ANS Admin — Agent Naming Service</title>
<style>
  * {{ margin:0; padding:0; box-sizing:border-box; }}
  body {{ font-family:-apple-system,BlinkMacSystemFont,sans-serif; background:#f1f5f9; color:#0f172a; }}
  .header {{ background:linear-gradient(135deg,#0f172a,#1e3a5f); padding:16px 24px; display:flex; align-items:center; justify-content:space-between; }}
  .header h1 {{ color:white; font-size:18px; }}
  .header span {{ color:rgba(255,255,255,0.5); font-size:12px; }}
  .tabs {{ background:white; padding:8px 24px; border-bottom:1px solid #e2e8f0; display:flex; gap:4px; }}
  .content {{ max-width:1200px; margin:24px auto; padding:0 24px; }}
  .card {{ background:white; border:1px solid #e2e8f0; border-radius:8px; padding:20px; margin-bottom:16px; }}
  .stat-grid {{ display:grid; grid-template-columns:repeat(4,1fr); gap:16px; margin-bottom:24px; }}
  .stat {{ background:white; border:1px solid #e2e8f0; border-radius:8px; padding:16px; text-align:center; }}
  .stat .num {{ font-size:28px; font-weight:800; color:#0891b2; }}
  .stat .label {{ font-size:11px; color:#64748b; text-transform:uppercase; margin-top:4px; }}
  table {{ width:100%; border-collapse:collapse; font-size:13px; }}
  th {{ background:#f8fafc; padding:8px 12px; text-align:left; font-size:11px; text-transform:uppercase; color:#64748b; border-bottom:1px solid #e2e8f0; }}
  td {{ padding:8px 12px; border-bottom:1px solid #f1f5f9; }}
  tr:hover {{ background:#f8fafc; }}
  .badge {{ display:inline-block; padding:2px 8px; border-radius:10px; font-size:10px; font-weight:700; }}
  .badge-green {{ background:#dcfce7; color:#15803d; }}
  .badge-yellow {{ background:#fef3c7; color:#92400e; }}
  .badge-red {{ background:#fee2e2; color:#991b1b; }}
  .badge-grey {{ background:#f1f5f9; color:#64748b; }}
  .btn {{ padding:6px 14px; border-radius:6px; font-size:12px; font-weight:600; border:none; cursor:pointer; text-decoration:none; display:inline-block; }}
  .btn-primary {{ background:#0891b2; color:white; }}
  .btn-danger {{ background:#ef4444; color:white; }}
  .btn-outline {{ background:white; border:1px solid #e2e8f0; color:#475569; }}
  h2 {{ font-size:18px; margin-bottom:12px; }}
  h3 {{ font-size:14px; color:#475569; margin-bottom:8px; }}
</style>
</head>
<body>
  <div class="header">
    <div>
      <h1>ANS Admin — Agent Naming Service</h1>
      <span>trustmodel.ai/ans · Separate from enterprise console</span>
    </div>
    <div style="display:flex;gap:8px;">
      <a href="/docs" class="btn btn-outline" target="_blank">API Docs</a>
      <a href="https://trustmodel.ai/ans" class="btn btn-outline" target="_blank">Public Page</a>
      <a href="/admin/logout" class="btn btn-outline" style="color:#ef4444;border-color:#fecaca;">Logout</a>
    </div>
  </div>
  <div class="tabs">{tab_html}</div>
  <div class="content">{content}</div>
</body>
</html>"""


@router.get("/admin", response_class=HTMLResponse)
def admin_overview(request: Request, session: Session = Depends(get_session)):
    """Admin overview dashboard."""

    admin = get_current_admin(request, session)
    if not admin:
        return RedirectResponse("/admin/login")

    agents = session.exec(select(Agent)).all()
    transfers = session.exec(select(Transfer)).all()
    lookups = session.exec(select(func.count(LookupLog.id))).one()

    verified = len([a for a in agents if a.verified])
    avg_score = sum(a.trust_score or 0 for a in agents) / max(len(agents), 1)
    orphans = len([a for a in agents if a.orphan_risk != "none"])
    pending_transfers = len([t for t in transfers if t.status == "pending"])

    # Recent agents
    recent = sorted(agents, key=lambda a: a.registered_at, reverse=True)[:10]
    recent_rows = ""
    for a in recent:
        v_badge = '<span class="badge badge-green">Verified</span>' if a.verified else '<span class="badge badge-grey">Unverified</span>'
        tier_class = "badge-green" if "Trusted" in a.trust_tier else "badge-yellow" if "Safe" in a.trust_tier else "badge-red"
        recent_rows += f"""<tr>
            <td><strong>{a.ans_name}</strong></td>
            <td>{a.owner_org}</td>
            <td>{v_badge}</td>
            <td><span class="badge {tier_class}">{a.trust_score} — {a.trust_tier}</span></td>
            <td>{a.agent_type}</td>
            <td>{a.registered_at.strftime('%Y-%m-%d')}</td>
        </tr>"""

    content = f"""
    <div class="stat-grid">
        <div class="stat"><div class="num">{len(agents)}</div><div class="label">Total Agents</div></div>
        <div class="stat"><div class="num">{verified}</div><div class="label">Verified Owners</div></div>
        <div class="stat"><div class="num">{pending_transfers}</div><div class="label">Pending Transfers</div></div>
        <div class="stat"><div class="num">{lookups}</div><div class="label">Total Lookups</div></div>
    </div>
    <div class="stat-grid">
        <div class="stat"><div class="num">{round(avg_score, 1)}</div><div class="label">Avg TrustScore</div></div>
        <div class="stat"><div class="num">{orphans}</div><div class="label">Orphan Risk</div></div>
        <div class="stat"><div class="num">{len(transfers)}</div><div class="label">Total Transfers</div></div>
        <div class="stat"><div class="num">{len([a for a in agents if a.trust_score and a.trust_score >= 8.0])}</div><div class="label">Highly Trusted</div></div>
    </div>

    <div class="card">
        <h2>Recent Registrations</h2>
        <table>
            <tr><th>ANS Name</th><th>Owner</th><th>Verified</th><th>TrustScore</th><th>Type</th><th>Registered</th></tr>
            {recent_rows if recent_rows else '<tr><td colspan="6" style="text-align:center;color:#94a3b8;padding:20px;">No agents registered yet. Use POST /ans/register to add the first one.</td></tr>'}
        </table>
    </div>
    """

    return admin_html(content, "overview")


@router.get("/admin/agents", response_class=HTMLResponse)
def admin_agents(request: Request, session: Session = Depends(get_session)):
    """All registered agents with edit/remove actions."""
    admin = get_current_admin(request, session)
    if not admin:
        return RedirectResponse("/admin/login")

    agents = session.exec(select(Agent).order_by(Agent.registered_at.desc())).all()

    rows = ""
    for a in agents:
        v_badge = '<span class="badge badge-green">✓</span>' if a.verified else '<span class="badge badge-grey">✗</span>'
        tier_class = "badge-green" if a.trust_score and a.trust_score >= 8.0 else "badge-yellow" if a.trust_score and a.trust_score >= 6.0 else "badge-red"
        rows += f"""<tr>
            <td><a href="/ans/lookup/{a.ans_name}" target="_blank"><strong>{a.ans_name}</strong></a></td>
            <td>{a.display_name}</td>
            <td>{a.owner_org}</td>
            <td>{a.owner_email}</td>
            <td>{v_badge}</td>
            <td><span class="badge {tier_class}">{a.trust_score}</span></td>
            <td>{a.agent_type}</td>
            <td>{a.status}</td>
            <td>
                <a href="/ans/cert/{a.ans_name}" target="_blank" class="btn btn-outline" style="font-size:10px;padding:3px 8px;">Cert</a>
            </td>
        </tr>"""

    content = f"""
    <div class="card">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">
            <h2>All Registered Agents ({len(agents)})</h2>
            <a href="/docs#/default/register_agent_ans_register_post" target="_blank" class="btn btn-primary">+ Register New Agent</a>
        </div>
        <table>
            <tr><th>ANS Name</th><th>Display Name</th><th>Owner</th><th>Email</th><th>Verified</th><th>Score</th><th>Type</th><th>Status</th><th>Actions</th></tr>
            {rows if rows else '<tr><td colspan="9" style="text-align:center;color:#94a3b8;padding:20px;">No agents registered yet.</td></tr>'}
        </table>
    </div>
    """

    return admin_html(content, "agents")


@router.get("/admin/transfers", response_class=HTMLResponse)
def admin_transfers(request: Request, session: Session = Depends(get_session)):
    """Ownership transfer history."""
    admin = get_current_admin(request, session)
    if not admin:
        return RedirectResponse("/admin/login")

    transfers = session.exec(select(Transfer).order_by(Transfer.initiated_at.desc())).all()

    rows = ""
    for t in transfers:
        status_class = "badge-green" if t.status == "completed" else "badge-yellow" if t.status == "pending" else "badge-red"
        rows += f"""<tr>
            <td><strong>{t.ans_name}</strong></td>
            <td>{t.from_org}<br><span style="font-size:10px;color:#94a3b8;">{t.from_email}</span></td>
            <td>→</td>
            <td>{t.to_org}<br><span style="font-size:10px;color:#94a3b8;">{t.to_email}</span></td>
            <td><span class="badge {status_class}">{t.status}</span></td>
            <td>{t.initiated_at.strftime('%Y-%m-%d %H:%M')}</td>
            <td>{t.completed_at.strftime('%Y-%m-%d %H:%M') if t.completed_at else '—'}</td>
        </tr>"""

    content = f"""
    <div class="card">
        <h2>Ownership Transfers ({len(transfers)})</h2>
        <table>
            <tr><th>Agent</th><th>From</th><th></th><th>To</th><th>Status</th><th>Initiated</th><th>Completed</th></tr>
            {rows if rows else '<tr><td colspan="7" style="text-align:center;color:#94a3b8;padding:20px;">No transfers yet.</td></tr>'}
        </table>
    </div>
    """

    return admin_html(content, "transfers")


@router.get("/admin/rankings", response_class=HTMLResponse)
def admin_rankings(request: Request, session: Session = Depends(get_session)):
    """Public TrustScore rankings across all categories."""
    admin = get_current_admin(request, session)
    if not admin:
        return RedirectResponse("/admin/login")

    content = """
    <div class="card">
        <h2>Public Trust Rankings</h2>
        <p style="color:#64748b;font-size:13px;margin-bottom:16px;">
            These are the public rankings pages on trustmodel.ai — managed separately from the enterprise console.
            All scores are based on public data. Vendors request detailed evaluations through /developers.
        </p>
        <div style="display:grid;grid-template-columns:repeat(2,1fr);gap:12px;">
            <div style="border:1px solid #e2e8f0;border-radius:8px;padding:16px;">
                <h3>🤖 Foundation Models (12)</h3>
                <p style="font-size:12px;color:#64748b;">GPT, Claude, Gemini, Llama rankings</p>
                <a href="https://trustmodel.ai/leaderboard" target="_blank" class="btn btn-outline" style="margin-top:8px;">View Rankings →</a>
            </div>
            <div style="border:1px solid #e2e8f0;border-radius:8px;padding:16px;">
                <h3>🏢 Enterprise COTS (42)</h3>
                <p style="font-size:12px;color:#64748b;">Salesforce, Workday, SAP, HubSpot rankings</p>
                <a href="https://trustmodel.ai/benchmark" target="_blank" class="btn btn-outline" style="margin-top:8px;">View Rankings →</a>
            </div>
            <div style="border:1px solid #e2e8f0;border-radius:8px;padding:16px;">
                <h3>🧩 Chrome Extensions (108)</h3>
                <p style="font-size:12px;color:#64748b;">Browser extension trust & safety scores</p>
                <a href="https://trustmodel.ai/chrome-extensions" target="_blank" class="btn btn-outline" style="margin-top:8px;">View Rankings →</a>
            </div>
            <div style="border:1px solid #e2e8f0;border-radius:8px;padding:16px;">
                <h3>🔌 MCP Servers (91)</h3>
                <p style="font-size:12px;color:#64748b;">MCP server tool safety rankings</p>
                <a href="https://trustmodel.ai/mcp-servers" target="_blank" class="btn btn-outline" style="margin-top:8px;">View Rankings →</a>
            </div>
        </div>
    </div>

    <div class="card">
        <h2>Badge System (239 badges live)</h2>
        <table>
            <tr><th>Type</th><th>Count</th><th>URL Pattern</th><th>Status</th></tr>
            <tr><td>MCP Servers</td><td>91</td><td><code>trustmodel.ai/badge/mcp/{slug}.svg</code></td><td><span class="badge badge-green">Live</span></td></tr>
            <tr><td>Chrome Extensions</td><td>108</td><td><code>trustmodel.ai/badge/chrome/{id}.svg</code></td><td><span class="badge badge-green">Live</span></td></tr>
            <tr><td>COTS Enterprise</td><td>40</td><td><code>trustmodel.ai/badge/cots/{slug}.svg</code></td><td><span class="badge badge-green">Live</span></td></tr>
            <tr><td>ANS Agents</td><td>—</td><td><code>trustmodel.ai/badge/ans/{name}.svg</code></td><td><span class="badge badge-yellow">On registration</span></td></tr>
        </table>
    </div>
    """

    return admin_html(content, "rankings")


@router.get("/admin/outreach", response_class=HTMLResponse)
def admin_outreach(request: Request, session: Session = Depends(get_session)):
    """GTM outreach tracking."""
    admin = get_current_admin(request, session)
    if not admin:
        return RedirectResponse("/admin/login")

    content = """
    <div class="card">
        <h2>GitHub Distribution</h2>
        <table>
            <tr><th>PR</th><th>Repository</th><th>Stars</th><th>Status</th></tr>
            <tr><td>#3910</td><td>modelcontextprotocol/servers (Official MCP)</td><td>16K+</td><td><span class="badge badge-yellow">Pending</span></td></tr>
            <tr><td>#758</td><td>e2b-dev/awesome-ai-agents</td><td>27K+</td><td><span class="badge badge-yellow">Pending</span></td></tr>
            <tr><td>#1077</td><td>mahseema/awesome-ai-tools</td><td>4.7K</td><td><span class="badge badge-yellow">Pending</span></td></tr>
            <tr><td>#22</td><td>Giskard-AI/awesome-ai-safety</td><td>212</td><td><span class="badge badge-yellow">Pending</span></td></tr>
            <tr><td>#35</td><td>xyNNN/awesome-chrome</td><td>106</td><td><span class="badge badge-yellow">Pending</span></td></tr>
        </table>
    </div>

    <div class="card">
        <h2>Published Tools</h2>
        <table>
            <tr><th>Tool</th><th>Repository</th><th>Status</th></tr>
            <tr><td>GitHub Action (MCP Trust Check)</td><td><a href="https://github.com/pdxlab/trustmodel-mcp-check" target="_blank">pdxlab/trustmodel-mcp-check</a></td><td><span class="badge badge-green">Published</span></td></tr>
            <tr><td>CLI Tool</td><td><a href="https://github.com/pdxlab/trustmodel-check" target="_blank">pdxlab/trustmodel-check</a></td><td><span class="badge badge-green">Published</span></td></tr>
            <tr><td>Chrome Extension</td><td><a href="https://github.com/pdxlab/trustmodel-browser-extension" target="_blank">pdxlab/trustmodel-browser-extension</a></td><td><span class="badge badge-yellow">Submitted to Store</span></td></tr>
            <tr><td>ANS Registry API</td><td><a href="https://github.com/pdxlab/ans-registry" target="_blank">pdxlab/ans-registry</a></td><td><span class="badge badge-green">Published</span></td></tr>
        </table>
    </div>

    <div class="card">
        <h2>Partnership Outreach</h2>
        <table>
            <tr><th>Partner</th><th>Ask</th><th>Status</th><th>Next Step</th></tr>
            <tr><td>Google Cloud Marketplace</td><td>Show TrustScore on AI app listings</td><td><span class="badge badge-yellow">Email ready</span></td><td>Send at Google NEXT</td></tr>
            <tr><td>HuggingFace</td><td>TrustScore on model cards</td><td><span class="badge badge-yellow">Email ready</span></td><td>Send this week</td></tr>
            <tr><td>Anthropic / MCP</td><td>ANS verification in MCP protocol</td><td><span class="badge badge-green">PR submitted</span></td><td>Follow up at NEXT</td></tr>
            <tr><td>Chrome Web Store</td><td>TrustScore in extension pages</td><td><span class="badge badge-yellow">Email ready</span></td><td>Send via GCP contact</td></tr>
            <tr><td>npm / PyPI</td><td>TrustScore badges on AI packages</td><td><span class="badge badge-grey">Later</span></td><td>After badge adoption</td></tr>
        </table>
    </div>

    <div class="card">
        <h2>Social Media Cards</h2>
        <table>
            <tr><th>Card</th><th>Target</th><th>Schedule</th><th>Status</th></tr>
            <tr><td>COTS Top 5</td><td>@Salesforce @Atlassian @Box @Zendesk @Asana</td><td>Mon Apr 14</td><td><span class="badge badge-yellow">Ready</span></td></tr>
            <tr><td>Chrome Ext Top 5</td><td>@GoogleChrome @brave</td><td>Wed Apr 16</td><td><span class="badge badge-yellow">Ready</span></td></tr>
            <tr><td>MCP Servers Top 5</td><td>@AnthropicAI @GoogleMaps @brave</td><td>Fri Apr 18</td><td><span class="badge badge-yellow">Ready</span></td></tr>
        </table>
    </div>

    <div class="card">
        <h2>Press Releases</h2>
        <table>
            <tr><th>Release</th><th>Headline</th><th>Status</th></tr>
            <tr><td>Chrome Extensions</td><td>108 extensions scored, 63% warrant caution</td><td><span class="badge badge-green">Ready</span></td></tr>
            <tr><td>HR AI Benchmark</td><td>9 of 15 fail NYC LL144 bias audit</td><td><span class="badge badge-green">Ready</span></td></tr>
            <tr><td>AI Litigation Tracker</td><td>61 lawsuits — untested AI is the next asbestos</td><td><span class="badge badge-green">Ready</span></td></tr>
        </table>
    </div>
    """

    return admin_html(content, "outreach")
