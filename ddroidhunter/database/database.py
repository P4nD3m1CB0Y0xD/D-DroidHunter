import duckdb
from logging import INFO

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


def create_db_table(database_path: str) -> bool:
    try:
        con = duckdb.connect(database=database_path)
        con.execute("CREATE TABLE samples (samples STRING USING COMPRESSION zstd)")
        con.close()
        log.info(f"DB - Databased '{database_path}' created successfuly")
    except Exception as e:
        log.error(f"DB - Error while creating database: '{database_path}'")


def value_exists(database_path: str, value: str) -> bool:
    con = duckdb.connect(database=database_path)
    r = con.execute("SELECT 1 FROM samples WHERE samples = ? LIMIT 1", [value]).fetchone()
    con.close()
    return r is not None


def insert_sample_into_db(database_path: str, sample: str):
    try:
        con = duckdb.connect(database=database_path)
        # Create table (if not exists, to avoid errors when re-running)
        con.execute("CREATE TABLE IF NOT EXISTS samples (samples STRING USING COMPRESSION zstd)")
        if not value_exists(database_path, sample):
            con.execute("INSERT INTO samples VALUES (?)", [sample])
            log.info(f"DB - Sample '{sample}' insert into database")
        else:
            log.error(f"DB - Sample '{sample}' already present into database")
        con.close()
    except Exception as e:
        log.error(f"DB - Error while insert data into database: {sample}")
