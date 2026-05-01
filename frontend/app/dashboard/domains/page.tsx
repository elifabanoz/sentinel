"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { domains, type Domain } from "@/lib/api";

const STATUS_COLORS: Record<string, string> = {
  PENDING:  "text-[var(--muted-foreground)] border-[var(--border)]",
  VERIFIED: "text-emerald-400 border-emerald-400",
  FAILED:   "text-[var(--destructive)] border-[var(--destructive)]",
};

export default function DomainsPage() {
  const router = useRouter();
  const [domainList, setDomainList] = useState<Domain[]>([]);
  const [newDomain, setNewDomain] = useState("");
  const [adding, setAdding] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    domains.list().then(setDomainList).catch(() => router.push("/login"));
  }, [router]);

  async function addDomain(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setAdding(true);
    try {
      const domain = await domains.add(newDomain.trim());
      setDomainList((prev) => [domain, ...prev]);
      setNewDomain("");
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to add domain");
    } finally {
      setAdding(false);
    }
  }

  async function verify(id: string) {
    try {
      const updated = await domains.verify(id);
      setDomainList((prev) => prev.map((d) => (d.id === id ? updated : d)));
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Verification failed");
    }
  }

  return (
    <div className="max-w-2xl space-y-8">
      <h1 className="text-xl font-semibold">Domains</h1>

      <form onSubmit={addDomain} className="flex gap-3">
        <input
          type="text"
          required
          value={newDomain}
          onChange={(e) => setNewDomain(e.target.value)}
          placeholder="example.com"
          className="flex-1 rounded-md border border-[var(--border)] bg-[var(--input)] px-3 py-2 text-sm text-[var(--foreground)] placeholder:text-[var(--muted-foreground)] focus:outline-none focus:ring-1 focus:ring-[var(--primary)]"
        />
        <button
          type="submit"
          disabled={adding}
          className="rounded-md bg-[var(--primary)] px-4 py-2 text-sm font-medium text-[var(--primary-foreground)] hover:bg-[var(--accent)] disabled:opacity-50 transition-colors"
        >
          {adding ? "Adding…" : "Add domain"}
        </button>
      </form>

      {error && <p className="text-sm text-[var(--destructive)]">{error}</p>}

      <div className="space-y-3">
        {domainList.map((domain) => (
          <div
            key={domain.id}
            className="rounded-lg border border-[var(--border)] bg-[var(--card)] p-5 space-y-3"
          >
            <div className="flex items-center justify-between">
              <span className="font-mono text-sm">{domain.name}</span>
              <span
                className={`text-xs border rounded-full px-2.5 py-0.5 font-mono ${STATUS_COLORS[domain.status] ?? ""}`}
              >
                {domain.status}
              </span>
            </div>

            {domain.status === "PENDING" && (
              <>
                <div className="rounded-md bg-[var(--secondary)] px-4 py-3 space-y-1">
                  <p className="text-xs text-[var(--muted-foreground)]">
                    Add this DNS TXT record to verify ownership:
                  </p>
                  <p className="font-mono text-xs text-[var(--primary)] break-all">
                    {domain.txtRecord}
                  </p>
                </div>
                <button
                  onClick={() => verify(domain.id)}
                  className="text-sm text-[var(--primary)] hover:underline"
                >
                  I've added it — verify now →
                </button>
              </>
            )}
          </div>
        ))}

        {domainList.length === 0 && (
          <div className="rounded-lg border border-[var(--border)] bg-[var(--card)] p-10 text-center">
            <p className="text-sm text-[var(--muted-foreground)]">
              No domains added yet.
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
