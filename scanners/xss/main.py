import json
import logging
import os
import time

import pika
import psycopg2

from sentinel_core import ScanTarget, ScanConfig
from scanner import XssScanner

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

RABBIT_HOST = os.getenv("RABBITMQ_HOST", "localhost")
RABBIT_USER = os.getenv("RABBITMQ_USER", "sentinel")
RABBIT_PASS = os.getenv("RABBITMQ_PASS", "sentinel_dev_pass")
DB_URL = os.getenv("DATABASE_URL", "postgresql://sentinel:sentinel_dev_pass@localhost:5432/sentinel")

QUEUE_NAME = "scan.xss"
scanner = XssScanner()


def get_db_connection():
    return psycopg2.connect(DB_URL)


def save_findings(findings, scan_id: str):
    if not findings:
        return
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            for f in findings:
                cur.execute(
                    """
                    INSERT INTO findings
                        (scan_id, severity, owasp_category, title, description, evidence, remediation, cvss_score)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (scan_id, f.severity.value, f.owasp_category,
                     f.title, f.description, f.evidence, f.remediation, f.cvss_score),
                )
        conn.commit()
    finally:
        conn.close()


def process_message(ch, method, properties, body):
    try:
        job = json.loads(body)
        target = ScanTarget(url=job["url"], scan_id=job["scan_id"], domain=job["domain"])
        config = ScanConfig(max_requests_per_second=5, request_timeout=10)

        log.info(f"Starting XSS scan for {target.domain}")
        findings = scanner.scan(target, config)
        log.info(f"Found {len(findings)} XSS issues")

        save_findings(findings, job["scan_id"])
        ch.basic_ack(delivery_tag=method.delivery_tag)

    except Exception as e:
        log.error(f"Error: {e}")
        ch.basic_nack(delivery_tag=method.delivery_tag, requeue=True)


def connect_with_retry(max_retries=10, delay=5):
    for attempt in range(max_retries):
        try:
            credentials = pika.PlainCredentials(RABBIT_USER, RABBIT_PASS)
            return pika.BlockingConnection(
                pika.ConnectionParameters(host=RABBIT_HOST, credentials=credentials)
            )
        except Exception as e:
            log.warning(f"RabbitMQ not ready ({attempt + 1}/{max_retries}): {e}")
            time.sleep(delay)
    raise RuntimeError("Could not connect to RabbitMQ")


def main():
    log.info("XSS Scanner worker starting...")
    connection = connect_with_retry()
    channel = connection.channel()
    channel.queue_declare(queue=QUEUE_NAME, durable=True)
    channel.basic_qos(prefetch_count=1)
    channel.basic_consume(queue=QUEUE_NAME, on_message_callback=process_message)
    log.info(f"Waiting for jobs on '{QUEUE_NAME}'...")
    channel.start_consuming()


if __name__ == "__main__":
    main()
