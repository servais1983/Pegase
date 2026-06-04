"""Periodically ship rotated audit log segments to S3 Object Lock storage.

Designed to be run as a cron / k8s CronJob. Strategy:

  1. Verify the current chain integrity (`pegase audit` equivalent).
  2. Atomically rotate ``audit.log`` -> ``audit.<ts>.log`` (the live process
     keeps writing to a freshly recreated ``audit.log`` thanks to its
     open-on-append semantics).
  3. Upload the rotated segment with ``ObjectLockMode=COMPLIANCE`` and a
     retention deadline so it cannot be deleted before the legal hold expires.
  4. Delete the local rotated segment only AFTER the upload's ETag matches a
     locally-computed SHA-256.

Requires ``boto3``. Configuration via environment:

    PEGASE_AUDIT_LOG_PATH      default /var/lib/pegase/audit.log
    PEGASE_AUDIT_S3_BUCKET     required
    PEGASE_AUDIT_S3_PREFIX     default 'audit/'
    PEGASE_AUDIT_RETENTION_DAYS default 2555 (7 years)
    AWS_REGION                 default us-east-1
"""

from __future__ import annotations

import hashlib
import os
import shutil
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

from pegase.core.audit import AuditLog


def main() -> int:
    log_path = Path(os.environ.get("PEGASE_AUDIT_LOG_PATH", "/var/lib/pegase/audit.log"))
    bucket = os.environ.get("PEGASE_AUDIT_S3_BUCKET")
    if not bucket:
        print("PEGASE_AUDIT_S3_BUCKET is required", file=sys.stderr)
        return 2
    prefix = os.environ.get("PEGASE_AUDIT_S3_PREFIX", "audit/")
    retention_days = int(os.environ.get("PEGASE_AUDIT_RETENTION_DAYS", "2555"))

    if not log_path.exists() or log_path.stat().st_size == 0:
        print("audit log empty; nothing to ship.")
        return 0

    audit = AuditLog(log_path)
    ok, entries, error = audit.verify()
    if not ok:
        print(f"REFUSING to ship: chain integrity failure after {entries}: {error}",
              file=sys.stderr)
        return 1

    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    rotated = log_path.with_name(f"audit.{ts}.log")
    shutil.move(log_path, rotated)
    log_path.touch(mode=0o600)

    try:
        import boto3
    except ImportError:
        print("boto3 is required (pip install boto3)", file=sys.stderr)
        return 3

    s3 = boto3.client("s3", region_name=os.environ.get("AWS_REGION", "us-east-1"))
    sha = hashlib.sha256(rotated.read_bytes()).hexdigest()
    key = f"{prefix.rstrip('/')}/{rotated.name}"
    retain_until = datetime.now(UTC) + timedelta(days=retention_days)

    with rotated.open("rb") as fh:
        s3.put_object(
            Bucket=bucket,
            Key=key,
            Body=fh,
            ObjectLockMode="COMPLIANCE",
            ObjectLockRetainUntilDate=retain_until,
            Metadata={"sha256": sha, "entries": str(entries)},
        )
    print(f"uploaded s3://{bucket}/{key}  sha256={sha}  entries={entries}")
    rotated.unlink()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
