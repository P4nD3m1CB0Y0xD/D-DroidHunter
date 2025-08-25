import time
import json
from logging import INFO

from logger.logger import Logger
from utils.utils import get_argument_parsed, delete_all_files
from virustotal.virustotal import get_virustotal_data
from database.database import create_db_table, insert_sample_into_db
from mobsf.mobsf import file_upload, scan_file

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


def init(
        vt_apikey: str,
        mobsf_apikey: str,
        mobsf_url: str,
        json_dir: str,
        samples_dir: str,
        pdr_dir: str = None,
        db_dir: str = None
    ):
    db = db_dir + "/ddroidhunter.db"
    create_db_table(database_path=db)

    vt_results = get_virustotal_data(
        apikey=vt_apikey, 
        output_samples_directory=samples_dir,
        database_dir=db
    )

    mobsf_results = list()

    for result in vt_results:
        insert_sample_into_db(database_path=db, sample=result["sha256"])
        full_filename = samples_dir + "/" + (result["sha256"] + ".apk")
        uploaded_file = file_upload(apikey=mobsf_apikey, mobsf_url=mobsf_url, filename=full_filename)
        scanned_result = scan_file(apikey=mobsf_apikey, mobsf_url=mobsf_url, data=uploaded_file)
        mobsf_results.append(scanned_result)

    final_data = {
        "virustotal_results": vt_results,
        "mobsf_results": mobsf_results
    }

    output = json_dir + "/" + "report_" + str(time.time()) + ".json"
    with open(output, "w", encoding="utf-8") as f:
        json.dump(final_data, f, indent=4, ensure_ascii=False)    


def main() -> None:
    args_ctl = get_argument_parsed()
    args = args_ctl.parse_args()

    try:
        log.info("Starting execute D-DroidHunter")
        init(
            vt_apikey=args.vt_apikey,
            mobsf_apikey=args.mobsf_apikey,
            mobsf_url=args.mobsf_url,
            json_dir=args.json_reports,
            samples_dir=args.samples_dir,
            pdr_dir=args.pdf_reports,
            db_dir=args.database_dir
        )
    finally:
        delete_all_files(directory=args.samples_dir)
        log.warning("All samples were removed")


if __name__ == "__main__":
    main()
