#!/usr/bin/env python3
"""Download SBOMs from MinIO for advisories_only mode."""
import logging
import os
import sys

logger = logging.getLogger(__name__)

import boto3
from botocore.config import Config

def main():
    output_dir = sys.argv[1] if len(sys.argv) > 1 else "/scanner/input/sboms"
    org = os.environ.get("ORG_LABEL", "")
    if not org:
        logger.error("[!] ORG_LABEL not set")
        sys.exit(1)

    client = boto3.client(
        "s3",
        endpoint_url=os.environ["S3_ENDPOINT"],
        aws_access_key_id=os.environ["S3_ACCESS_KEY"],
        aws_secret_access_key=os.environ["S3_SECRET_KEY"],
        region_name=os.environ.get("S3_REGION", "us-east-1"),
        config=Config(signature_version="s3v4"),
    )

    os.makedirs(output_dir, exist_ok=True)
    prefix = f"{org}/"
    paginator = client.get_paginator("list_objects_v2")
    count = 0

    for page in paginator.paginate(Bucket="sboms", Prefix=prefix):
        for obj in page.get("Contents", []):
            key = obj["Key"]
            if key.endswith("/sbom.json"):
                repo = key.replace(prefix, "").replace("/sbom.json", "").replace("/", "__")
                path = os.path.join(output_dir, f"{repo}.json")
                client.download_file("sboms", key, path)
                count += 1

    logger.info("[+] Downloaded %d SBOMs from MinIO", count)

if __name__ == "__main__":
    main()
