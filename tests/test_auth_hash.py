"""
Argon2 hashing + legacy SHA-256 compatibility tests.
"""

from __future__ import annotations

from app.auth import (
    AdminUser,
    _legacy_hash,
    hash_password,
    is_legacy_hash,
    upgrade_hash_if_legacy,
    verify_password,
)


def test_new_hash_is_argon2():
    h = hash_password("hunter2")
    assert h.startswith("$argon2")
    assert not is_legacy_hash(h)


def test_argon2_verifies_correct_password():
    h = hash_password("correct-horse")
    assert verify_password("correct-horse", salt="", password_hash=h)


def test_argon2_rejects_wrong_password():
    h = hash_password("correct-horse")
    assert not verify_password("battery-staple", salt="", password_hash=h)


def test_legacy_sha256_hash_is_detected():
    salt = "deadbeef"
    legacy = _legacy_hash("hunter2", salt)
    assert is_legacy_hash(legacy)
    assert len(legacy) == 64


def test_legacy_password_verifies_through_compat_path():
    salt = "deadbeef"
    legacy = _legacy_hash("hunter2", salt)
    assert verify_password("hunter2", salt=salt, password_hash=legacy)
    assert not verify_password("wrong", salt=salt, password_hash=legacy)


def test_login_with_legacy_hash_upgrades_to_argon2(session):
    """Successful login on a legacy-hash row should rewrite the hash."""
    salt = "abc123"
    legacy = _legacy_hash("hunter2", salt)
    admin = AdminUser(
        email="legacy@example.com",
        name="Legacy",
        password_hash=legacy,
        salt=salt,
        role="admin",
    )
    session.add(admin)
    session.commit()
    session.refresh(admin)
    assert is_legacy_hash(admin.password_hash)

    # Simulate the successful-login codepath.
    assert verify_password("hunter2", admin.salt, admin.password_hash)
    upgrade_hash_if_legacy(admin, "hunter2", session)
    session.refresh(admin)

    assert admin.password_hash.startswith("$argon2")
    assert admin.salt == ""
    # And the password still verifies against the new hash.
    assert verify_password("hunter2", admin.salt, admin.password_hash)


def test_upgrade_noop_for_argon2_rows(session):
    admin = AdminUser(
        email="modern@example.com",
        name="Modern",
        password_hash=hash_password("pw"),
        salt="",
        role="admin",
    )
    session.add(admin)
    session.commit()
    session.refresh(admin)
    before = admin.password_hash

    upgrade_hash_if_legacy(admin, "pw", session)
    session.refresh(admin)
    assert admin.password_hash == before  # unchanged
