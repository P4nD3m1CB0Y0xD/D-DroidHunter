import requests
from logging import INFO
from simdjson import Parser
from logger.logger import Logger

from utils.utils import check_file
from database.database import value_exists

_VT_RULE = [
    "Android_Ghost_NFC"
]

VT_URL = "https://www.virustotal.com/api/v3"


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

parser = Parser()


def parse_androguard_data(androguard_data) -> dict:
    parsed_androguard_data = {
        "androguard_package": androguard_data.get("Package"),
        "androguard_main_activity": androguard_data.get("main_activity"),
        "androguard_activities": androguard_data.get("Activities"),
        "androguard_services": androguard_data.get("Services"),
        "androguard_providers": androguard_data.get("Providers"),
        "androguard_receivers": androguard_data.get("Receivers"),
    }
    return parsed_androguard_data


def parse_virustotal_data(raw_data: dict) -> list:
    vt_alerts_results = list()

    nested_data: dict = parser.parse(raw_data["message"]).as_dict()
    for data in nested_data.get("data"):
        rule_name = data["context_attributes"]["rule_name"]
        if rule_name in _VT_RULE:
            results_data = {
                "sha256": data.get("id"),
                "last_analysis_stats": f"Total: ({data["attributes"]["last_analysis_stats"]["malicious"]}/{data["attributes"]["last_analysis_stats"]["undetected"]})",
                "common_names": data.get("attributes").get("names"),
                "androguard_results": parse_androguard_data(androguard_data=data["attributes"]["androguard"])

            }           
            vt_alerts_results.append(results_data)

    return vt_alerts_results


def download_vt_sample(apikey: str, sample_hash: str, output_dir: str, db_dir: str) -> bool:
    headers = {
        "accept": "application/json",
        "x-apikey": apikey
    }

    full_filename = output_dir + "/" + (sample_hash + ".apk")

    if not check_file(full_filename) and not value_exists(db_dir, sample_hash): 
        try:
            log.info(f"VT - Starting downloading sample '{sample_hash}'")
            resp = requests.get(
                url=VT_URL + f"/files/{sample_hash}/download",
                headers=headers
            )

            with open(full_filename, "wb") as f:
                f.write(resp.content)
            log.info(f"VT - Sample '{sample_hash}' downloaded successfully")
            return True
        except Exception as e:
            log.error(f"VT - Error while downloading sample '{sample_hash}': {e}")
            return False
    log.info(f"VT - File '{sample_hash}' already present.")
    return False


def get_virustotal_notified_samples(apikey: str) -> dict:
    headers = {
        "x-apikey": apikey
    }

    try:
        log.info("VT - Requesting notified samples")
        resp = requests.get(
            url=VT_URL + "/intelligence/hunting_notification_files",
            headers=headers
        )

        if resp.status_code != 200:
            log.error(f"VT - Status code different than 200: Status {resp.status_code}")
            return {"status": False, "message": resp.text}
        return {"status": True, "message": resp.text}
    except Exception as e:
        return {"status": False, "message": e}


def get_virustotal_data(apikey: str, output_samples_directory: str, database_dir: str):
    log.info("VT - Getting VirusTotal data")
    data: dict = get_virustotal_notified_samples(apikey=apikey)

    if data["status"]:
        parsed_vt_data = parse_virustotal_data(raw_data=data)

        for d in parsed_vt_data:
            if download_vt_sample(
                    apikey=apikey, 
                    sample_hash=d["sha256"], 
                    output_dir=output_samples_directory,
                    db_dir=database_dir
                ):
                continue
            else:
                log.error(f"VT - Error couldn't download sample '{d["sha256"]}'")
        return parsed_vt_data
    else:
        log.error(f"VT - Failed to request notified data: {data["message"]}")

