# ADR-0002 — RabbitMQ as Message Broker

**Date:** 2026-04-30  

## Context

Scanner jobs need to be dispatched from the API Gateway to the appropriate scanner workers asynchronously. We needed a message broker that supports reliable delivery, so a scan job is never silently lost even if a worker crashes mid-execution.

The main alternatives considered were RabbitMQ and Apache Kafka.

## Decision

We chose RabbitMQ.

## Reasons

- **Manual acknowledgment (ack/nack):** A scanner worker only acknowledges a job after it finishes processing. If the worker crashes, RabbitMQ redelivers the job automatically.
- **Dead letter queue (DLQ):** After a configurable number of retries, failed jobs are routed to a DLQ for inspection  no silent failures.
- **Per-scanner queues:** Each scanner has its own queue (`scan.tls`, `scan.sqli`, etc.), making routing straightforward.
- **Simpler operational model:** Kafka requires managing topics, partitions, and consumer offsets. For a job queue with ~5 message types and no need for log replay, RabbitMQ is the appropriate tool.

## Consequences

**Positive:**

- Reliable job delivery with built-in retry and DLQ support.
- Simple to reason about: a message is either in a queue, being processed, or in the DLQ.
- Management UI available at port 15672 for visibility.

**Negative:**

- No message replay (unlike Kafka). Once a message is consumed and acked, it is gone.
- Not suited for high-throughput event streaming use cases (not needed here).

