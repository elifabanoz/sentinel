import logging
from datetime import timezone, datetime

import psycopg2

log = logging.getLogger(__name__)

TOTAL_SCANNERS = 5


def complete_scan_job(db_url: str, scan_id: str) -> None:
    """
    Bir scanner job'ı başarıyla bitince çağrılır.
    completed_jobs atomik olarak artırılır; 5'e ulaşınca scan COMPLETED olur.
    Row-level lock sayesinde eş zamanlı worker'larda race condition olmaz.
    """
    conn = psycopg2.connect(db_url)
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE scans
                SET
                    completed_jobs = completed_jobs + 1,
                    progress       = LEAST((completed_jobs + 1) * 20, 100),
                    status         = CASE
                                         WHEN completed_jobs + 1 >= %s THEN 'COMPLETED'
                                         ELSE 'RUNNING'
                                     END,
                    finished_at    = CASE
                                         WHEN completed_jobs + 1 >= %s THEN NOW()
                                         ELSE NULL
                                     END
                WHERE id = %s
                """,
                (TOTAL_SCANNERS, TOTAL_SCANNERS, scan_id),
            )
        conn.commit()
        log.info(f"Scan {scan_id}: job completed, progress updated")
    finally:
        conn.close()


def fail_scan(db_url: str, scan_id: str) -> None:
    """
    Bir scanner job'ı DLQ'ya düştüğünde çağrılır.
    Scan'i hemen FAILED olarak işaretler.
    """
    conn = psycopg2.connect(db_url)
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE scans
                SET status = 'FAILED', finished_at = NOW()
                WHERE id = %s AND status != 'FAILED'
                """,
                (scan_id,),
            )
        conn.commit()
        log.error(f"Scan {scan_id}: marked as FAILED")
    finally:
        conn.close()
