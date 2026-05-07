"""Shared RabbitMQ queue declaration for scanner workers.

Queue arguments here MUST stay in sync with Spring's RabbitConfig.scanQueue()
in api-gateway/src/main/java/io/sentinel/gateway/config/RabbitConfig.java.
A mismatch causes RabbitMQ to reject the redeclare with PRECONDITION_FAILED
(406), which closes the channel and crashes the worker.
"""

SCAN_QUEUE_ARGUMENTS = {
    "x-dead-letter-exchange": "sentinel.dlx",
    "x-dead-letter-routing-key": "dlq",
}


def declare_scan_queue(channel, queue_name: str):
    channel.queue_declare(
        queue=queue_name,
        durable=True,
        arguments=SCAN_QUEUE_ARGUMENTS,
    )
