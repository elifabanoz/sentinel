import logging
import os
import time

import pika
import psycopg2

from sentinel_core import ScanTarget, ScanConfig, RateLimiter
from sentinel_core.worker_base import process_with_retry
from sentinel_core.scan_reporter import complete_scan_job, fail_scan
from scanner import TlsScanner

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

RABBIT_HOST = os.getenv("RABBITMQ_HOST", "localhost")
RABBIT_USER = os.getenv("RABBITMQ_USER", "sentinel")
RABBIT_PASS = os.getenv("RABBITMQ_PASS", "sentinel_dev_pass")
DB_URL = os.getenv("DATABASE_URL", "postgresql://sentinel:sentinel_dev_pass@localhost:5432/sentinel")

QUEUE_NAME = "scan.tls"
scanner = TlsScanner()
rate_limiter = RateLimiter(redis_host=os.getenv("REDIS_HOST", "localhost"))


def get_db_connection():
    return psycopg2.connect(DB_URL)


def save_findings(findings, scan_id: str):
    if not findings:
        return

    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            for f in findings:
                # ON CONFLICT DO NOTHING: idempotency garantisi
                # Aynı job iki kez çalışsa aynı finding iki kez yazılmaz
                cur.execute(
                    """
                    INSERT INTO findings
                        (scan_id, severity, owasp_category, title, description, evidence, remediation, cvss_score)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (scan_id, title, evidence) DO NOTHING
                    """,
                    (scan_id, f.severity.value, f.owasp_category,
                     f.title, f.description, f.evidence, f.remediation, f.cvss_score),
                )
        conn.commit()
        log.info(f"Saved {len(findings)} findings for scan {scan_id}")
    finally:
        conn.close()


def handle_job(job: dict):
    scan_id = job["scan_id"]
    url = job["url"]
    domain = job["domain"]

    log.info(f"Starting TLS scan for {domain} (scan_id={scan_id})")
    rate_limiter.acquire(domain)

    target = ScanTarget(url=url, scan_id=scan_id, domain=domain)
    config = ScanConfig(max_requests_per_second=5, request_timeout=10)

    findings = scanner.scan(target, config)
    log.info(f"Found {len(findings)} issues for {domain}")

    save_findings(findings, scan_id)
    complete_scan_job(DB_URL, scan_id)


def on_failure(job: dict):
    fail_scan(DB_URL, job["scan_id"])


def on_message(ch, method, properties, body):
    process_with_retry(ch, method, properties, body, handle_job, on_failure)


def connect_with_retry(max_retries=10, delay=5):
    for attempt in range(max_retries):
        try:
            credentials = pika.PlainCredentials(RABBIT_USER, RABBIT_PASS)
            params = pika.ConnectionParameters(host=RABBIT_HOST, credentials=credentials)
            return pika.BlockingConnection(params)
        except Exception as e:
            log.warning(f"RabbitMQ not ready (attempt {attempt + 1}/{max_retries}): {e}")
            time.sleep(delay)
    raise RuntimeError("Could not connect to RabbitMQ after retries")


def main():
    log.info("TLS Scanner worker starting...")
    connection = connect_with_retry()
    channel = connection.channel()

    channel.queue_declare(queue=QUEUE_NAME, durable=True)
    channel.basic_qos(prefetch_count=1)
    channel.basic_consume(queue=QUEUE_NAME, on_message_callback=on_message)

    log.info(f"Waiting for jobs on queue '{QUEUE_NAME}'...")
    channel.start_consuming()


if __name__ == "__main__":
    main()
