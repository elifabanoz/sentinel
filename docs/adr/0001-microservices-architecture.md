# ADR-0001 — Microservices Architecture

**Date:** 2026-04-30

## Context

Sentinel runs five different types of security scans: TLS/headers, SQL injection, XSS, OSINT, and dependency CVE checks. These scans are computationally independent, one does not need the result of another to start or finish. The question was whether to build them as a single application (monolith) or as separate services.

## Decision

We chose a microservices architecture. Each scanner is a separate Python/FastAPI service that consumes jobs from its own RabbitMQ queue and writes findings directly to PostgreSQL.

## Consequences

**Positive:**

- All five scanners run in parallel for a given scan, reducing total scan time.
- A crash in one scanner does not affect the others, fault isolation is built in.
- Each scanner can be scaled, deployed, and updated independently.
- Different tech stacks per service are possible (Java for the gateway, Python for scanners).

**Negative:**

- More operational complexity: more services to run, monitor, and debug.
- Local development requires Docker Compose to wire everything together.
- Distributed tracing and logging are harder than in a monolith.

