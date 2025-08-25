import json
import requests
from logging import INFO
from pathlib import Path
from requests_toolbelt.multipart.encoder import MultipartEncoder

from logger.logger import Logger

log = Logger(
    __name__,
    log_file="logs/app_log.json",
    level=INFO,
    ecs_like=True,
    static_fields={"service.name": "d-droidhunter", "env": "dev"},
    redacted_keys={"api_key"},
    max_bytes=5 * 1024 * 1024,
    backup_count=3,
    fsync=True
).get()


def file_upload(apikey: str, mobsf_url: str, filename: str) -> dict | None:
    # Resolve and validate path early
    path = Path(filename).expanduser().resolve()

    if not path.is_file():
        # Log the exact path tried and bail early
        log.error(f"MobSF - Sample not found: {path}")
        return None

    try:
        log.info("MobSF - Uploading file...")
        with path.open("rb") as fh:
            multipart_data = MultipartEncoder(
                fields={
                    "file": (path.name, fh, "application/octet-stream")
                }
            )

            headers = {
                "Content-Type": multipart_data.content_type,
                "Authorization": apikey
            }

            r = requests.post(
                f"{mobsf_url.rstrip('/')}/api/v1/upload",
                data=multipart_data,
                headers=headers,
                timeout=60
            )
            r.raise_for_status()
            return r.text
    except requests.HTTPError as http_err:
        log.error(f"MobSF - HTTP error {r.status_code}: {r.text}")
    except Exception as e:
        log.exception("MobSF - Error while uploading sample to MobSF")
    return None


def parse_result_data(data: dict) -> dict:
    d = json.loads(data)

    data_parsed = {
        "file_name": d["file_name"],
        "app_name": d["app_name"],
        "size": d["size"],
        "package_name": d["package_name"],
        "main_activity": d["main_activity"],
        "target_sdk": d["target_sdk"],
        "min_sdk": d["min_sdk"],
        "hashes": {
            "md5": d["md5"],
            "sha1": d["sha1"],
            "sha256": d["sha256"]
        },
        "app_components": {
            "activities": d["activities"],
            "receivers": d["receivers"],
            "providers": d["providers"],
            "services": d["services"]
        },
        "permissions": d["permissions"],
        "urls": d["urls"],
        "secrets": d["secrets"]
    }
    
    return data_parsed



def scan_file(apikey: str, mobsf_url: str, data: dict) -> dict | None:
    log.info("MobSF - Scanning file...")

    d = json.loads(data)

    headers = {
        "Authorization": apikey
    }

    try:
        r = requests.post(
            f"{mobsf_url.rstrip('/')}/api/v1/scan",
            data=d,
            headers=headers
        )
        data = parse_result_data(r.text)
        return data
    except Exception as e:
        log.error(f"MobSF - Error while scanning sample: {e}")
