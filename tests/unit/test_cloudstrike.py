"""CloudStrike tests — boto3 is fully faked, no real AWS calls are made."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from pegase.core.scope import ActionType, Scope, ScopeGuard, ScopeRule, ScopeViolation
from pegase.modules.cloudstrike import CloudStrike

ACCOUNT_ID = "123456789012"


def _guard(pattern: str = f"aws:{ACCOUNT_ID}") -> ScopeGuard:
    scope = Scope(
        rules=[ScopeRule(pattern)],
        allowed_actions={ActionType.ACTIVE},
        authorization_token="t",
        starts_at=datetime.now(UTC),
    )
    return ScopeGuard(scope)


class _NoSuchEntity(Exception):
    pass


class _Exceptions:
    NoSuchEntityException = _NoSuchEntity


class _Paginator:
    def __init__(self, pages: list[dict]) -> None:
        self._pages = pages

    def paginate(self, **kw):
        return iter(self._pages)


class _FakeSTS:
    def get_caller_identity(self):
        return {"Account": ACCOUNT_ID}


class _FakeS3:
    def __init__(self, buckets, pab_raises, acl_grants):
        self._buckets = buckets
        self._pab_raises = pab_raises
        self._acl_grants = acl_grants

    def list_buckets(self):
        return {"Buckets": [{"Name": n} for n in self._buckets]}

    def get_public_access_block(self, Bucket):
        if self._pab_raises:
            raise RuntimeError("no public access block")
        return {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            }
        }

    def get_bucket_acl(self, Bucket):
        return {"Grants": self._acl_grants.get(Bucket, [])}


class _FakeIAM:
    exceptions = _Exceptions

    def __init__(self, password_policy, users, mfa_by_user, keys_by_user):
        self._password_policy = password_policy
        self._users = users
        self._mfa_by_user = mfa_by_user
        self._keys_by_user = keys_by_user

    def get_account_password_policy(self):
        if self._password_policy is None:
            raise self.exceptions.NoSuchEntityException()
        return {"PasswordPolicy": self._password_policy}

    def get_paginator(self, name):
        assert name == "list_users"
        return _Paginator([{"Users": [{"UserName": u} for u in self._users]}])

    def list_mfa_devices(self, UserName):
        return {"MFADevices": self._mfa_by_user.get(UserName, [])}

    def list_access_keys(self, UserName):
        return {"AccessKeyMetadata": self._keys_by_user.get(UserName, [])}


class _FakeEC2:
    def __init__(self, security_groups):
        self._sgs = security_groups

    def get_paginator(self, name):
        assert name == "describe_security_groups"
        return _Paginator([{"SecurityGroups": self._sgs}])


class _FakeSession:
    def __init__(self, s3, iam, ec2):
        self._s3 = s3
        self._iam = iam
        self._ec2 = ec2

    def client(self, name, region_name=None):
        return {"sts": _FakeSTS(), "s3": self._s3, "iam": self._iam, "ec2": self._ec2}[name]


def _patch_session(monkeypatch, s3, iam, ec2):
    def factory(profile_name=None, region_name=None):
        return _FakeSession(s3, iam, ec2)

    monkeypatch.setattr("boto3.Session", factory)


@pytest.mark.asyncio
async def test_cloudstrike_flags_public_bucket_and_weak_password_policy(monkeypatch):
    s3 = _FakeS3(
        buckets=["public-bucket"],
        pab_raises=True,
        acl_grants={},
    )
    iam = _FakeIAM(
        password_policy={
            "MinimumPasswordLength": 6,
            "RequireSymbols": False,
            "RequireNumbers": False,
            "MaxPasswordAge": 0,
        },
        users=[],
        mfa_by_user={},
        keys_by_user={},
    )
    ec2 = _FakeEC2(security_groups=[])
    _patch_session(monkeypatch, s3, iam, ec2)

    result = await CloudStrike().run(targets=[], guard=_guard())

    titles = [f.title for f in result.findings]
    assert any("S3 bucket potentially public: public-bucket" in t for t in titles)
    assert any("Weak IAM password policy" in t for t in titles)
    assert result.raw["account_id"] == ACCOUNT_ID


@pytest.mark.asyncio
async def test_cloudstrike_no_password_policy_is_high_severity(monkeypatch):
    s3 = _FakeS3(buckets=[], pab_raises=False, acl_grants={})
    iam = _FakeIAM(password_policy=None, users=[], mfa_by_user={}, keys_by_user={})
    ec2 = _FakeEC2(security_groups=[])
    _patch_session(monkeypatch, s3, iam, ec2)

    result = await CloudStrike().run(targets=[], guard=_guard())
    match = next(f for f in result.findings if "No IAM password policy" in f.title)
    assert match.severity == "high"


@pytest.mark.asyncio
async def test_cloudstrike_flags_users_without_mfa_and_stale_keys(monkeypatch):
    s3 = _FakeS3(buckets=[], pab_raises=False, acl_grants={})
    old_date = datetime.now(UTC) - timedelta(days=200)
    iam = _FakeIAM(
        password_policy={
            "MinimumPasswordLength": 20,
            "RequireSymbols": True,
            "RequireNumbers": True,
            "MaxPasswordAge": 90,
        },
        users=["alice"],
        mfa_by_user={"alice": []},
        keys_by_user={"alice": [{"AccessKeyId": "AKIAFAKE", "CreateDate": old_date}]},
    )
    ec2 = _FakeEC2(security_groups=[])
    _patch_session(monkeypatch, s3, iam, ec2)

    result = await CloudStrike().run(targets=[], guard=_guard())
    titles = [f.title for f in result.findings]
    assert any("IAM user without MFA: alice" in t for t in titles)
    assert any("Stale access key" in t and "alice" in t for t in titles)


@pytest.mark.asyncio
async def test_cloudstrike_flags_open_security_group(monkeypatch):
    s3 = _FakeS3(buckets=[], pab_raises=False, acl_grants={})
    iam = _FakeIAM(
        password_policy={
            "MinimumPasswordLength": 20,
            "RequireSymbols": True,
            "RequireNumbers": True,
            "MaxPasswordAge": 90,
        },
        users=[],
        mfa_by_user={},
        keys_by_user={},
    )
    sg = {
        "GroupId": "sg-123",
        "GroupName": "open-ssh",
        "IpPermissions": [
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    }
    ec2 = _FakeEC2(security_groups=[sg])
    _patch_session(monkeypatch, s3, iam, ec2)

    result = await CloudStrike().run(targets=[], guard=_guard())
    titles = [f.title for f in result.findings]
    assert any("sg-123" in t and "0.0.0.0/0" in t for t in titles)


@pytest.mark.asyncio
async def test_cloudstrike_enforces_scope_guard(monkeypatch):
    s3 = _FakeS3(buckets=[], pab_raises=False, acl_grants={})
    iam = _FakeIAM(password_policy=None, users=[], mfa_by_user={}, keys_by_user={})
    ec2 = _FakeEC2(security_groups=[])
    _patch_session(monkeypatch, s3, iam, ec2)

    # Scope only covers a different account, so the resolved account should
    # be rejected by the ScopeGuard.
    with pytest.raises(ScopeViolation):
        await CloudStrike().run(targets=[], guard=_guard("aws:999999999999"))
