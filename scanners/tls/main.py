import json
import logging
import os
import time

import pika
import psycopg2

from sentinel_core import ScanTarget, ScanConfig
from scanner import TlsScanner

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

RABBIT_HOST = os.getenv("RABBITMQ_HOST", "localhost")
RABBIT_USER = os.getenv("RABBITMQ_USER", "sentinel")
RABBIT_PASS = os.getenv("RABBITMQ_PASS", "sentinel_dev_pass")
DB_URL = os.getenv("DATABASE_URL", "postgresql://sentinel:sentinel_dev_pass@localhost:5432/sentinel")

QUEUE_NAME = "scan.tls"
scanner = TlsScanner()


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
        log.info(f"Saved {len(findings)} findings for scan {scan_id}")
    finally:
        conn.close()


def process_message(ch, method, properties, body):
    """
    RabbitMQ'dan gelen her job mesajını işler.
    Manuel ack: işlem bitmeden mesaj queue'da kalır, crash durumunda kaybolmaz.
    """
    try:
        job = json.loads(body)
        scan_id = job["scan_id"]
        url = job["url"]
        domain = job["domain"]

        log.info(f"Starting TLS scan for {domain} (scan_id={scan_id})")

        target = ScanTarget(url=url, scan_id=scan_id, domain=domain)
        config = ScanConfig(max_requests_per_second=5, request_timeout=10)

        findings = scanner.scan(target, config)
        log.info(f"Found {len(findings)} issues for {domain}")

        save_findings(findings, scan_id)

        # Başarılı  mesajı queue'dan sil
        ch.basic_ack(delivery_tag=method.delivery_tag)

    except Exception as e:
        log.error(f"Error processing message: {e}")
        # Başarısız  mesajı queue'ya geri koy (retry mekanizması devreye girer)
        ch.basic_nack(delivery_tag=method.delivery_tag, requeue=True)


def connect_with_retry(max_retries=10, delay=5):
    """RabbitMQ hazır olana kadar bekler — docker-compose'da sıralama için"""
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

    # Queue yoksa oluştur idempotent işlem
    channel.queue_declare(queue=QUEUE_NAME, durable=True)

    # Aynı anda sadece 1 mesaj al işlem bitmeden yeni mesaj gelmesin
    channel.basic_qos(prefetch_count=1)
    channel.basic_consume(queue=QUEUE_NAME, on_message_callback=process_message)

    log.info(f"Waiting for jobs on queue '{QUEUE_NAME}'...")
    channel.start_consuming()


if __name__ == "__main__":
    main()
