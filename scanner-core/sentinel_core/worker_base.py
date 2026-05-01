import json
import logging
import time

import pika

log = logging.getLogger(__name__)

# Exponential backoff bekleme süreleri 
RETRY_DELAYS = [1, 5, 30]
MAX_RETRIES = 3


def get_retry_count(properties) -> int:
    """Read retry count from message header."""
    headers = properties.headers or {}
    return headers.get("x-retry-count", 0)


def process_with_retry(ch, method, properties, body, handler_fn):
    """
    Tüm scanner worker'larının kullandığı ortak retry mekanizması.
    handler_fn başarısız olursa exponential backoff ile tekrar dener.
    MAX_RETRIES aşılınca nack + requeue=False : RabbitMQ DLX'e düşer.
    """
    retry_count = get_retry_count(properties)

    try:
        handler_fn(json.loads(body))
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
            ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False)
