# Sentinel

A web application security scanner built with microservices. Sentinel runs five scanners in parallel — TLS/headers, SQL injection, XSS, OSINT, and dependency vulnerabilities — and presents findings in a dashboard.

## Architecture

```
Next.js frontend → Spring Boot API Gateway → RabbitMQ → Python scanner workers → PostgreSQL
                                           ↘ Redis (rate limiting)
```

Each scanner operates independently. If one crashes, the others continue. All five run in parallel for a given scan, so total scan time equals the slowest scanner — not the sum of all five.

See [ARCHITECTURE.md](ARCHITECTURE.md) and [docs/adr/](docs/adr/) for design decisions.

## Stack

| Layer | Technology |
|---|---|
| API Gateway | Spring Boot 3, Java 21 |
| Scanners | Python 3.11, FastAPI |
| Message queue | RabbitMQ 3.13 |
| Cache / rate limit | Redis 7 |
| Database | PostgreSQL 16 |
| Frontend | Next.js 15, Tailwind CSS |
| Migrations | Flyway |
| CI | GitHub Actions |

## Getting started

**Prerequisites:** Docker, Docker Compose

```bash
git clone https://github.com/your-username/sentinel.git
cd sentinel
docker compose up --build
```

- Frontend: http://localhost:3000
- API Gateway: http://localhost:8080
- RabbitMQ management: http://localhost:15672 (sentinel / sentinel_dev_pass)

## How it works

1. Register an account and add your domain
2. Add the DNS TXT record shown in the UI to verify ownership
3. Click **Start scan** — five jobs are dispatched to RabbitMQ queues simultaneously
4. Watch progress in real time as each scanner completes
5. Review findings grouped by severity with CVSS scores and remediation steps

## Scanners

| Scanner | What it checks |
|---|---|
| TLS | TLS version, certificate expiry, security headers (HSTS, CSP, X-Frame-Options) |
| SQLi | Error-based, time-based, boolean-based SQL injection |
| XSS | Reflected XSS via forms, query parameters, and HTTP headers |
| OSINT | DNS zone transfer, SPF/DMARC records, subdomain enumeration |
| Dependencies | Known CVEs in requirements.txt / package.json / pom.xml via OSV.dev |

## Security model

- Domain ownership is verified via DNS TXT record before any active scan
- Rate limiting is enforced per domain using a Redis token bucket
- Failed jobs retry with exponential backoff (1s → 5s → 30s), then go to a dead letter queue
- JWT is stored in an HttpOnly cookie — not accessible to JavaScript

## Development

Run scanner tests:

```bash
cd scanners
pip install -r tests/requirements.txt
pytest tests/ -v
```

Run API Gateway:

```bash
cd api-gateway
mvn spring-boot:run
```

Run integration tests against OWASP Juice Shop:

```bash
docker compose --profile dev up juice-shop -d
cd scanners && pytest tests/ -v
```
