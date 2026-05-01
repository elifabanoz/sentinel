"use client";

import { useEffect, useState, useCallback } from "react";
import { useParams, useRouter } from "next/navigation";
import Link from "next/link";
import { scans, type Scan, type Finding } from "@/lib/api";

const SEVERITY_CLASS: Record<string, string> = {
  CRITICAL: "severity-critical",
  HIGH:     "severity-high",
  MEDIUM:   "severity-medium",
  LOW:      "severity-low",
  INFO:     "severity-info",
};

const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

export default function ScanDetailPage() {
  const { id } = useParams<{ id: string }>();
  const router = useRouter();
  const [scan, setScan] = useState<Scan | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [filter, setFilter] = useState("ALL");
  const [expanded, setExpanded] = useState<string | null>(null);

  const fetchScan = useCallback(async () => {
    const data = await scans.get(id);
    setScan(data);
    return data;
  }, [id]);

  // Status polling
  useEffect(() => {
    fetchScan().catch(() => router.push("/login"));

    const interval = setInterval(async () => {
      const data = await fetchScan();
      if (data.status === "COMPLETED" || data.status === "FAILED") {
        clearInterval(interval);
        if (data.status === "COMPLETED") {
          scans.findings(id).then(setFindings);
        }
      }
    }, 3000);

    return () => clearInterval(interval);
  }, [id, router, fetchScan]);

  // İlk yüklemede tamamlanmış scan'in bulgularını getir
  useEffect(() => {
    if (scan?.status === "COMPLETED") {
      scans.findings(id).then(setFindings);
    }
  }, [scan?.status, id]);

  const filtered = filter === "ALL"
    ? findings
    : findings.filter((f) => f.severity === filter);

  const counts = SEVERITY_ORDER.reduce<Record<string, number>>((acc, s) => {
    acc[s] = findings.filter((f) => f.severity === s).length;
    return acc;
  }, {});

  if (!scan) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <p className="text-sm text-[var(--muted-foreground)]">Loading…</p>
      </div>
    );
  }

  return (
    <div className="min-h-screen p-8 max-w-4xl mx-auto space-y-8">
      <div className="space-y-1">
        <Link
          href="/dashboard"
          className="text-xs text-[var(--muted-foreground)] hover:text-[var(--primary)] transition-colors"
        >
          ← Back to scans
        </Link>
        <h1 className="text-xl font-semibold font-mono">{scan.domainName}</h1>
        <p className="text-xs text-[var(--muted-foreground)]">
          Started {new Date(scan.startedAt).toLocaleString()}
        </p>
      </div>

      {(scan.status === "QUEUED" || scan.status === "RUNNING") && (
        <div className="rounded-lg border border-[var(--primary)] bg-[var(--card)] p-6 space-y-3">
          <div className="flex items-center justify-between text-sm">
            <span className="text-[var(--primary)] font-mono">{scan.status}</span>
            <span className="text-[var(--muted-foreground)]">{scan.progress}%</span>
          </div>
          <div className="h-1.5 rounded-full bg-[var(--border)]">
            <div
              className="h-1.5 rounded-full bg-[var(--primary)] transition-all duration-700"
              style={{ width: `${scan.progress}%` }}
            />
          </div>
          <p className="text-xs text-[var(--muted-foreground)]">
            Running 5 scanners in parallel — TLS, SQLi, XSS, OSINT, Dependencies
          </p>
        </div>
      )}

      {scan.status === "FAILED" && (
        <div className="rounded-lg border border-[var(--destructive)] bg-[var(--card)] p-6">
          <p className="text-sm text-[var(--destructive)]">
            Scan failed. Check that the domain is reachable and try again.
          </p>
        </div>
      )}

      {scan.status === "COMPLETED" && (
        <div className="space-y-5">
          <div className="flex flex-wrap gap-2">
            <button
              onClick={() => setFilter("ALL")}
              className={`text-xs border rounded-full px-3 py-1 transition-colors ${
                filter === "ALL"
                  ? "border-[var(--primary)] text-[var(--primary)]"
                  : "border-[var(--border)] text-[var(--muted-foreground)] hover:border-[var(--foreground)]"
              }`}
            >
              All ({findings.length})
            </button>
            {SEVERITY_ORDER.filter((s) => counts[s] > 0).map((s) => (
              <button
                key={s}
                onClick={() => setFilter(s)}
                className={`text-xs border rounded-full px-3 py-1 transition-colors ${
                  filter === s
                    ? SEVERITY_CLASS[s]
                    : "border-[var(--border)] text-[var(--muted-foreground)] hover:border-[var(--foreground)]"
                }`}
              >
                {s} ({counts[s]})
              </button>
            ))}
          </div>

          {filtered.length === 0 ? (
            <div className="rounded-lg border border-[var(--border)] bg-[var(--card)] p-10 text-center">
              <p className="text-sm text-[var(--muted-foreground)]">No findings for this filter.</p>
            </div>
          ) : (
            <div className="space-y-2">
              {filtered.map((f) => (
                <div
                  key={f.id}
                  className="rounded-lg border border-[var(--border)] bg-[var(--card)] overflow-hidden"
                >
                  <button
                    onClick={() => setExpanded(expanded === f.id ? null : f.id)}
                    className="w-full flex items-center justify-between px-5 py-4 text-left hover:bg-[var(--secondary)] transition-colors"
                  >
                    <div className="flex items-center gap-3">
                      <span className={`text-xs border rounded-full px-2.5 py-0.5 font-mono ${SEVERITY_CLASS[f.severity]}`}>
                        {f.severity}
                      </span>
                      <span className="text-sm">{f.title}</span>
                    </div>
                    <span className="text-[var(--muted-foreground)] text-xs">
                      {expanded === f.id ? "▲" : "▼"}
                    </span>
                  </button>

                  {expanded === f.id && (
                    <div className="px-5 pb-5 space-y-4 border-t border-[var(--border)]">
                      <div className="pt-4 grid grid-cols-2 gap-4 text-xs text-[var(--muted-foreground)]">
                        <span>CVSS: <span className="text-[var(--foreground)] font-mono">{f.cvssScore}</span></span>
                        <span>OWASP: <span className="text-[var(--foreground)]">{f.owaspCategory}</span></span>
                      </div>
                      <div>
                        <p className="text-xs text-[var(--muted-foreground)] mb-1">Description</p>
                        <p className="text-sm whitespace-pre-wrap">{f.description}</p>
                      </div>
                      <div>
                        <p className="text-xs text-[var(--muted-foreground)] mb-1">Evidence</p>
                        <p className="font-mono text-xs bg-[var(--secondary)] rounded p-3 break-all">{f.evidence}</p>
                      </div>
                      <div>
                        <p className="text-xs text-[var(--muted-foreground)] mb-1">Remediation</p>
                        <p className="text-sm">{f.remediation}</p>
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
