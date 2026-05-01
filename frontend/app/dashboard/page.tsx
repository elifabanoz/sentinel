"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { scans, domains, type Scan, type Domain } from "@/lib/api";

const STATUS_COLORS: Record<string, string> = {
  QUEUED:    "text-[var(--muted-foreground)] border-[var(--border)]",
  RUNNING:   "text-[var(--primary)] border-[var(--primary)]",
  COMPLETED: "text-emerald-400 border-emerald-400",
  FAILED:    "text-[var(--destructive)] border-[var(--destructive)]",
};

export default function DashboardPage() {
  const router = useRouter();
  const [scanList, setScanList] = useState<Scan[]>([]);
  const [domainList, setDomainList] = useState<Domain[]>([]);
  const [selectedDomain, setSelectedDomain] = useState("");
  const [starting, setStarting] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    const token = localStorage.getItem("sentinel_token");
    if (!token) { router.push("/login"); return; }

    scans.list().then(setScanList).catch(() => router.push("/login"));
    domains.list().then((list) => {
      const verified = list.filter((d) => d.status === "VERIFIED");
      setDomainList(verified);
      if (verified.length > 0) setSelectedDomain(verified[0].id);
    });
  }, [router]);

  async function startScan() {
    if (!selectedDomain) return;
    setError("");
    setStarting(true);
    try {
      await scans.create(selectedDomain);
      const updated = await scans.list();
      setScanList(updated);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to start scan");
    } finally {
      setStarting(false);
    }
  }

  return (
    <div className="max-w-4xl space-y-8">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold">Scans</h1>

        <div className="flex items-center gap-3">
          {domainList.length === 0 ? (
            <Link
              href="/dashboard/domains"
              className="text-sm text-[var(--primary)] hover:underline"
            >
              Add a verified domain first →
            </Link>
          ) : (
            <>
              <select
                value={selectedDomain}
                onChange={(e) => setSelectedDomain(e.target.value)}
                className="rounded-md border border-[var(--border)] bg-[var(--input)] px-3 py-1.5 text-sm text-[var(--foreground)] focus:outline-none focus:ring-1 focus:ring-[var(--primary)]"
              >
                {domainList.map((d) => (
                  <option key={d.id} value={d.id}>{d.name}</option>
                ))}
              </select>
              <button
                onClick={startScan}
                disabled={starting}
                className="rounded-md bg-[var(--primary)] px-4 py-1.5 text-sm font-medium text-[var(--primary-foreground)] hover:bg-[var(--accent)] disabled:opacity-50 transition-colors"
              >
                {starting ? "Starting…" : "Start scan"}
              </button>
            </>
          )}
        </div>
      </div>

      {error && <p className="text-sm text-[var(--destructive)]">{error}</p>}

      {scanList.length === 0 ? (
        <div className="rounded-lg border border-[var(--border)] bg-[var(--card)] p-12 text-center">
          <p className="text-[var(--muted-foreground)] text-sm">No scans yet.</p>
        </div>
      ) : (
        <div className="space-y-2">
          {scanList.map((scan) => (
            <Link
              key={scan.id}
              href={`/scans/${scan.id}`}
              className="flex items-center justify-between rounded-lg border border-[var(--border)] bg-[var(--card)] px-5 py-4 hover:border-[var(--primary)] transition-colors group"
            >
              <div className="space-y-1">
                <p className="text-sm font-medium group-hover:text-[var(--primary)] transition-colors">
                  {scan.domainName}
                </p>
                <p className="text-xs text-[var(--muted-foreground)]">
                  {new Date(scan.startedAt).toLocaleString()}
                </p>
              </div>

              <div className="flex items-center gap-4">
                {scan.status === "RUNNING" && (
                  <div className="w-32">
                    <div className="h-1 rounded-full bg-[var(--border)]">
                      <div
                        className="h-1 rounded-full bg-[var(--primary)] transition-all"
                        style={{ width: `${scan.progress}%` }}
                      />
                    </div>
                    <p className="text-xs text-[var(--muted-foreground)] mt-1 text-right">
                      {scan.progress}%
                    </p>
                  </div>
                )}

                <span
                  className={`text-xs border rounded-full px-2.5 py-0.5 font-mono ${STATUS_COLORS[scan.status] ?? ""}`}
                >
                  {scan.status}
                </span>
              </div>
            </Link>
          ))}
        </div>
      )}
    </div>
  );
}
