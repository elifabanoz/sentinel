const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8080";

async function request<T>(
  path: string,
  options: RequestInit = {}
): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    ...options,
    credentials: "include",
    headers: {
      "Content-Type": "application/json",
      ...options.headers,
    },
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || res.statusText);
  }

  const text = await res.text();
  return text ? JSON.parse(text) : ({} as T);
}

export const auth = {
  register: (email: string, password: string) =>
    request<void>("/auth/register", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    }),
  login: (email: string, password: string) =>
    request<void>("/auth/login", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    }),
  logout: () => request<void>("/auth/logout", { method: "POST" }),
  me: () => request<{ email: string }>("/auth/me"),
};

export type Domain = {
  id: string;
  name: string;
  status: "PENDING" | "VERIFIED" | "FAILED";
  verificationToken: string;
};

export const domains = {
  list: () => request<Domain[]>("/domains"),
  add: (name: string) =>
    request<Domain>("/domains", { method: "POST", body: JSON.stringify({ name }) }),
  verify: (id: string) =>
    request<Domain>(`/domains/${id}/verify`, { method: "POST" }),
};

export type Scan = {
  id: string;
  domainName: string;
  status: "QUEUED" | "RUNNING" | "COMPLETED" | "FAILED";
  progress: number;
  startedAt: string;
  finishedAt: string | null;
};

export type Finding = {
  id: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  owaspCategory: string;
  title: string;
  description: string;
  evidence: string;
  remediation: string;
  cvssScore: number;
};

export const scans = {
  list: () => request<Scan[]>("/scans"),
  create: (domainId: string) =>
    request<{ scanId: string; statusUrl: string }>("/scans", {
      method: "POST",
      body: JSON.stringify({ domainId }),
    }),
  status: (id: string) =>
    request<{ scan_id: string; status: string; progress: number }>(
      `/scans/${id}/status`
    ),
  get: (id: string) => request<Scan>(`/scans/${id}`),
  findings: (id: string) => request<Finding[]>(`/scans/${id}/findings`),
};
