import json
import logging
import time

import pika

log = logging.getLogger(__name__)

RETRY_DELAYS = [1, 5, 30]
MAX_RETRIES = 3


def get_retry_count(properties) -> int:
    headers = properties.headers or {}
    return headers.get("x-retry-count", 0)


def process_with_retry(ch, method, properties, body, handler_fn, on_failure=None):
    """
    Tüm scanner worker'larının kullandığı ortak retry mekanizması.
    handler_fn başarısız olursa exponential backoff ile tekrar dener.
    MAX_RETRIES aşılınca nack + requeue=False : RabbitMQ DLX'e düşer.
    on_failure: DLQ'ya düşünce çağrılan opsiyonel callback(job: dict)
    """
    retry_count = get_retry_count(properties)
    job = json.loads(body)

    try:
        handler_fn(job)
        ch.basic_ack(delivery_tag=method.delivery_tag)

    except Exception as e:
        log.error(f"Error processing message (attempt {retry_count + 1}/{MAX_RETRIES}): {e}")

        if retry_count < MAX_RETRIES - 1:
            delay = RETRY_DELAYS[min(retry_count, len(RETRY_DELAYS) - 1)]
            log.info(f"Retrying in {delay}s...")
            time.sleep(delay)

            ch.basic_ack(delivery_tag=method.delivery_tag)
            ch.basic_publish(
                exchange="",
                routing_key=method.routing_key,
                body=body,
                properties=pika.BasicProperties(
                    headers={"x-retry-count": retry_count + 1},
                    delivery_mode=2,
                ),
            )
        else:
            log.error("Max retries exceeded. Sending to DLQ.")
            if on_failure:
                try:
                    on_failure(job)
                except Exception as cb_err:
                    log.error(f"on_failure callback error: {cb_err}")
            ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False)
