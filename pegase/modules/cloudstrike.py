"""CloudStrike - cloud security posture assessment (AWS, read-only).

CloudStrike performs **read-only** configuration checks against an AWS account
using credentials supplied out-of-band (an assumed read-only IAM role is
strongly recommended - e.g. the AWS-managed ``SecurityAudit`` policy). It never
mutates cloud state.

Targets are expressed as ``aws:<account-id>`` and must be covered by the
mission scope, so an operator cannot accidentally point CloudStrike at an
account they were not authorized to assess.

Checks implemented:
  * S3 buckets with public ACLs / public access block disabled,
  * IAM account password policy weaknesses,
  * IAM users without MFA,
  * access keys older than 90 days,
  * security groups exposing sensitive ports to 0.0.0.0/0.

``boto3`` is an optional dependency; the module raises a clear error if it is
not installed.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from pegase.core.logging import get_logger
from pegase.core.scope import ActionType, ScopeGuard
from pegase.modules.base import Finding, Module, ModuleResult

log = get_logger(__name__)

_SENSITIVE_PORTS = {22, 3389, 3306, 5432, 6379, 27017, 9200, 5984}
_KEY_MAX_AGE_DAYS = 90


class CloudStrike(Module):
    name = "cloudstrike"
    description = "Read-only AWS posture assessment (S3, IAM, security groups)."
    action_type = ActionType.ACTIVE

    async def run(
        self,
        *,
        targets: list[str],
        guard: ScopeGuard,
        parameters: dict[str, Any] | None = None,
    ) -> ModuleResult:
        params = parameters or {}
        region = params.get("region", "us-east-1")
        profile = params.get("aws_profile")

        try:
            import boto3
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(
                "boto3 is required for CloudStrike (pip install boto3)."
            ) from exc

        result = ModuleResult(module=self.name)
        session = boto3.Session(profile_name=profile, region_name=region)

        # Resolve the account id so we can scope-check it.
        sts = session.client("sts")
        account_id = sts.get_caller_identity()["Account"]
        target = f"aws:{account_id}"
        guard.check(target, self.action_type)
        log.info("cloudstrike_account", account=account_id, region=region)
        result.raw["account_id"] = account_id

        self._check_s3(session, target, result)
        self._check_iam(session, target, result)
        self._check_security_groups(session, target, result, region)
        return result

    # -- S3 ---------------------------------------------------------------

    def _check_s3(self, session, target: str, result: ModuleResult) -> None:
        s3 = session.client("s3")
        try:
            buckets = s3.list_buckets().get("Buckets", [])
        except Exception as exc:  # noqa: BLE001
            log.warning("s3_list_failed", error=str(exc))
            return
        for b in buckets:
            name = b["Name"]
            public = False
            reasons: list[str] = []
            try:
                pab = s3.get_public_access_block(Bucket=name)
                cfg = pab["PublicAccessBlockConfiguration"]
                if not all(cfg.values()):
                    public = True
                    reasons.append("public access block not fully enabled")
            except Exception:  # noqa: BLE001
                public = True
                reasons.append("no public access block configured")
            try:
                acl = s3.get_bucket_acl(Bucket=name)
                for grant in acl.get("Grants", []):
                    uri = grant.get("Grantee", {}).get("URI", "")
                    if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                        public = True
                        reasons.append(f"ACL grants to {uri}")
            except Exception:  # noqa: BLE001
                pass
            if public:
                result.findings.append(
                    Finding(
                        module=self.name,
                        target=f"{target}:s3:{name}",
                        title=f"S3 bucket potentially public: {name}",
                        description="; ".join(reasons),
                        severity="high",
                        evidence={"bucket": name, "reasons": reasons},
                        references=[
                            "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"
                        ],
                    )
                )

    # -- IAM --------------------------------------------------------------

    def _check_iam(self, session, target: str, result: ModuleResult) -> None:
        iam = session.client("iam")
        # Password policy
        try:
            policy = iam.get_account_password_policy()["PasswordPolicy"]
            weak: list[str] = []
            if policy.get("MinimumPasswordLength", 0) < 14:
                weak.append("min length < 14")
            if not policy.get("RequireSymbols"):
                weak.append("symbols not required")
            if not policy.get("RequireNumbers"):
                weak.append("numbers not required")
            if not policy.get("MaxPasswordAge"):
                weak.append("no password expiration")
            if weak:
                result.findings.append(
                    Finding(
                        module=self.name,
                        target=f"{target}:iam:password-policy",
                        title="Weak IAM password policy",
                        description="; ".join(weak),
                        severity="medium",
                        evidence={"policy": policy, "weaknesses": weak},
                    )
                )
        except iam.exceptions.NoSuchEntityException:
            result.findings.append(
                Finding(
                    module=self.name,
                    target=f"{target}:iam:password-policy",
                    title="No IAM password policy set",
                    description="The account has no password policy at all.",
                    severity="high",
                )
            )
        except Exception as exc:  # noqa: BLE001
            log.warning("iam_pwpolicy_failed", error=str(exc))

        # Users: MFA + key age
        try:
            paginator = iam.get_paginator("list_users")
            cutoff = datetime.now(UTC) - timedelta(days=_KEY_MAX_AGE_DAYS)
            for page in paginator.paginate():
                for user in page.get("Users", []):
                    uname = user["UserName"]
                    mfa = iam.list_mfa_devices(UserName=uname).get("MFADevices", [])
                    if not mfa:
                        result.findings.append(
                            Finding(
                                module=self.name,
                                target=f"{target}:iam:user:{uname}",
                                title=f"IAM user without MFA: {uname}",
                                description="Console-capable users should enforce MFA.",
                                severity="medium",
                                evidence={"user": uname},
                            )
                        )
                    keys = iam.list_access_keys(UserName=uname).get(
                        "AccessKeyMetadata", []
                    )
                    for k in keys:
                        created = k.get("CreateDate")
                        if created and created < cutoff:
                            age = (datetime.now(UTC) - created).days
                            result.findings.append(
                                Finding(
                                    module=self.name,
                                    target=f"{target}:iam:user:{uname}",
                                    title=f"Stale access key ({age}d) for {uname}",
                                    description=(
                                        f"Access key {k['AccessKeyId']} is {age} days "
                                        "old; rotate keys at least every 90 days."
                                    ),
                                    severity="medium",
                                    evidence={"user": uname, "age_days": age},
                                )
                            )
        except Exception as exc:  # noqa: BLE001
            log.warning("iam_users_failed", error=str(exc))

    # -- Security groups --------------------------------------------------

    def _check_security_groups(
        self, session, target: str, result: ModuleResult, region: str
    ) -> None:
        ec2 = session.client("ec2", region_name=region)
        try:
            paginator = ec2.get_paginator("describe_security_groups")
            for page in paginator.paginate():
                for sg in page.get("SecurityGroups", []):
                    for perm in sg.get("IpPermissions", []):
                        open_cidr = any(
                            rng.get("CidrIp") == "0.0.0.0/0"
                            for rng in perm.get("IpRanges", [])
                        )
                        if not open_cidr:
                            continue
                        from_port = perm.get("FromPort")
                        to_port = perm.get("ToPort")
                        exposed = _ports_in_range(from_port, to_port) & _SENSITIVE_PORTS
                        if exposed or from_port is None:
                            result.findings.append(
                                Finding(
                                    module=self.name,
                                    target=f"{target}:sg:{sg['GroupId']}",
                                    title=(
                                        f"Security group {sg['GroupId']} exposes "
                                        f"{'all ports' if from_port is None else sorted(exposed)} "
                                        "to 0.0.0.0/0"
                                    ),
                                    description=(
                                        f"SG '{sg.get('GroupName')}' allows inbound "
                                        f"{perm.get('IpProtocol')} "
                                        f"{from_port}-{to_port} from the entire internet."
                                    ),
                                    severity="high",
                                    evidence={"group_id": sg["GroupId"], "perm": str(perm)},
                                )
                            )
        except Exception as exc:  # noqa: BLE001
            log.warning("sg_describe_failed", error=str(exc))


def _ports_in_range(from_port: int | None, to_port: int | None) -> set[int]:
    if from_port is None or to_port is None:
        return set()
    if to_port - from_port > 1024:  # huge range -> treat as "all"
        return _SENSITIVE_PORTS
    return set(range(from_port, to_port + 1))
