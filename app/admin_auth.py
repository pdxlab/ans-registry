"""
Admin auth routes — login, logout, manage admins.
"""

from fastapi import APIRouter, Depends, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlmodel import Session, select

from .database import get_session
from .models import Agent
from .auth import (
    AdminUser,
    hash_password,
    upgrade_hash_if_legacy,
    verify_password,
    create_session,
    get_current_admin,
    require_admin,
    require_superadmin,
    SESSION_COOKIE,
    seed_superadmin,
)

# admin_html lives in admin.py
from .admin import admin_html

router = APIRouter()


@router.get("/admin/login", response_class=HTMLResponse)
def login_page(request: Request, session: Session = Depends(get_session)):
    """Login page."""
    # If already logged in, redirect to admin
    admin = get_current_admin(request, session)
    if admin:
        return RedirectResponse("/admin")

    error = request.query_params.get("error", "")
    error_html = f'<div style="background:#fee2e2;color:#991b1b;padding:8px 12px;border-radius:6px;font-size:13px;margin-bottom:12px;">{error}</div>' if error else ""

    return f"""<!DOCTYPE html>
<html>
<head><title>ANS Admin Login</title>
<style>
  body {{ font-family:-apple-system,sans-serif; background:#f1f5f9; display:flex; align-items:center; justify-content:center; min-height:100vh; margin:0; }}
  .login {{ background:white; border-radius:12px; padding:32px; width:360px; box-shadow:0 4px 20px rgba(0,0,0,0.1); }}
  .login h1 {{ font-size:20px; margin:0 0 4px; }}
  .login p {{ color:#64748b; font-size:13px; margin:0 0 20px; }}
  input {{ width:100%; padding:10px 12px; border:1px solid #e2e8f0; border-radius:6px; font-size:14px; margin-bottom:12px; box-sizing:border-box; }}
  button {{ width:100%; padding:10px; background:#0891b2; color:white; border:none; border-radius:6px; font-size:14px; font-weight:600; cursor:pointer; }}
  button:hover {{ background:#0e7490; }}
</style>
</head>
<body>
<div class="login">
  <h1>ANS Admin</h1>
  <p>Agent Naming Service — Admin Dashboard</p>
  {error_html}
  <form method="post" action="/admin/login">
    <input type="email" name="email" placeholder="Email" required />
    <input type="password" name="password" placeholder="Password" required />
    <button type="submit">Sign In</button>
  </form>
  <p style="margin-top:12px;font-size:11px;color:#94a3b8;text-align:center;">Separate from TrustModel enterprise console</p>
</div>
</body>
</html>"""


@router.post("/admin/login")
def login_submit(
    email: str = Form(...),
    password: str = Form(...),
    session: Session = Depends(get_session),
):
    """Process login."""
    admin = session.exec(select(AdminUser).where(AdminUser.email == email.lower())).first()

    if not admin or not admin.is_active:
        return RedirectResponse("/admin/login?error=Invalid+email+or+password", status_code=302)

    if not verify_password(password, admin.salt, admin.password_hash):
        return RedirectResponse("/admin/login?error=Invalid+email+or+password", status_code=302)

    # Successful login — opportunistically upgrade legacy SHA-256 hashes
    # to argon2 now that we have the plaintext password in memory.
    upgrade_hash_if_legacy(admin, password, session)

    # Create session
    session_id = create_session(admin, session)

    # Update last login
    from datetime import datetime
    admin.last_login = datetime.utcnow()
    session.add(admin)
    session.commit()

    response = RedirectResponse("/admin", status_code=302)
    response.set_cookie(SESSION_COOKIE, session_id, httponly=True, max_age=86400, samesite="lax")
    return response


@router.get("/admin/logout")
def logout():
    """Logout — clear session cookie."""
    response = RedirectResponse("/admin/login", status_code=302)
    response.delete_cookie(SESSION_COOKIE)
    return response


@router.get("/admin/users", response_class=HTMLResponse)
def admin_users(admin: AdminUser = Depends(require_superadmin), session: Session = Depends(get_session)):
    """Manage admin users — superadmin only."""

    users = session.exec(select(AdminUser)).all()

    rows = ""
    for u in users:
        role_badge = '<span style="background:#dcfce7;color:#15803d;padding:2px 8px;border-radius:10px;font-size:10px;font-weight:700;">superadmin</span>' if u.role == "superadmin" else '<span style="background:#e0f2fe;color:#0369a1;padding:2px 8px;border-radius:10px;font-size:10px;font-weight:700;">admin</span>' if u.role == "admin" else '<span style="background:#f1f5f9;color:#64748b;padding:2px 8px;border-radius:10px;font-size:10px;font-weight:700;">viewer</span>'
        active_badge = '<span style="color:#15803d;">●</span>' if u.is_active else '<span style="color:#dc2626;">●</span>'
        rows += f"""<tr>
            <td>{u.name}</td>
            <td>{u.email}</td>
            <td>{role_badge}</td>
            <td>{active_badge} {'Active' if u.is_active else 'Disabled'}</td>
            <td style="font-family:monospace;font-size:10px;">{u.api_key[:12]}...</td>
            <td>{u.last_login.strftime('%Y-%m-%d %H:%M') if u.last_login else 'Never'}</td>
        </tr>"""

    content = f"""
    <div class="card">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">
            <h2>Admin Users</h2>
        </div>
        <table>
            <tr><th>Name</th><th>Email</th><th>Role</th><th>Status</th><th>API Key</th><th>Last Login</th></tr>
            {rows}
        </table>
    </div>

    <div class="card">
        <h2>Add New Admin</h2>
        <form method="post" action="/admin/users/add" style="display:grid;grid-template-columns:1fr 1fr 1fr auto;gap:8px;align-items:end;">
            <div><label style="font-size:11px;color:#64748b;">Name</label><input type="text" name="name" required style="width:100%;padding:8px;border:1px solid #e2e8f0;border-radius:4px;font-size:13px;" /></div>
            <div><label style="font-size:11px;color:#64748b;">Email</label><input type="email" name="email" required style="width:100%;padding:8px;border:1px solid #e2e8f0;border-radius:4px;font-size:13px;" /></div>
            <div><label style="font-size:11px;color:#64748b;">Role</label><select name="role" style="width:100%;padding:8px;border:1px solid #e2e8f0;border-radius:4px;font-size:13px;"><option value="admin">Admin</option><option value="viewer">Viewer</option></select></div>
            <button type="submit" class="btn btn-primary" style="height:36px;">Add Admin</button>
        </form>
        <p style="font-size:11px;color:#94a3b8;margin-top:8px;">New admin will receive a temporary password. They must change it on first login.</p>
    </div>
    """

    return admin_html(content, "users")


@router.post("/admin/users/add")
def add_admin_user(
    name: str = Form(...),
    email: str = Form(...),
    role: str = Form("admin"),
    admin: AdminUser = Depends(require_superadmin),
    session: Session = Depends(get_session),
):
    """Add a new admin user — superadmin only."""
    import secrets as sec

    existing = session.exec(select(AdminUser).where(AdminUser.email == email.lower())).first()
    if existing:
        return RedirectResponse("/admin/users?error=Email+already+exists", status_code=302)

    temp_password = sec.token_hex(8)  # 16-char temporary password

    new_admin = AdminUser(
        email=email.lower(),
        name=name,
        password_hash=hash_password(temp_password),
        salt="",  # argon2 embeds its own salt
        role=role,
    )

    session.add(new_admin)
    session.commit()

    # In production, email the temp password. For now, show it in redirect.
    return RedirectResponse(f"/admin/users?added={email}&temp_pw={temp_password}", status_code=302)
