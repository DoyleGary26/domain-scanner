"use client";

import { useEffect, useId, useRef, useState, type FormEvent } from "react";
import type { CheckStatus, Grade, ScanCheck, ScanReport } from "@/lib/scanner";

const STATUS_RANK: Record<CheckStatus, number> = { fail: 0, warn: 1, pass: 2 };

const GRADE_STYLE: Record<Grade, string> = {
  A: "border-zinc-100 bg-card text-white",
  B: "border-zinc-400 bg-card text-zinc-100",
  C: "border-amber-700 bg-card text-amber-100",
  D: "border-orange-800 bg-card text-orange-100",
  F: "border-accent bg-accent/10 text-accent",
};

const STATUS_STYLE: Record<CheckStatus, string> = {
  pass: "border border-line bg-zinc-100/10 text-zinc-100",
  warn: "border border-amber-700 bg-amber-950/40 text-amber-100",
  fail: "border border-accent bg-accent text-white",
};

const STATUS_LABEL: Record<CheckStatus, string> = {
  pass: "Pass",
  warn: "Warning",
  fail: "Fail",
};

export default function Home() {
  const inputId = useId();
  const titleId = useId();
  const dialogRef = useRef<HTMLDialogElement>(null);
  const resultsRef = useRef<HTMLElement>(null);
  const [domain, setDomain] = useState("");
  const [report, setReport] = useState<ScanReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [unlockOpen, setUnlockOpen] = useState(false);

  useEffect(() => {
    const dialog = dialogRef.current;
    if (!dialog) return;
    if (unlockOpen && !dialog.open) dialog.showModal();
    if (!unlockOpen && dialog.open) dialog.close();
  }, [unlockOpen]);

  useEffect(() => {
    if (!report) return;
    resultsRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
  }, [report]);

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const nextDomain = domain.trim();
    if (!nextDomain || loading) return;

    setLoading(true);
    setError(null);
    setReport(null);

    try {
      const response = await fetch("/api/scan", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ domain: nextDomain }),
      });
      const payload: unknown = await response.json().catch(() => null);
      if (!response.ok) {
        setError(readError(payload, response.status));
        return;
      }
      if (!isReport(payload)) {
        setError("The scan returned an unexpected result.");
        return;
      }
      setReport(payload);
    } catch {
      setError("The scan could not be completed.");
    } finally {
      setLoading(false);
    }
  }

  const ranked = report ? rankIssues(report.checks) : [];
  const free = ranked.slice(0, 2);
  const freeIds = new Set(free.map((check) => check.id));
  const locked = report?.checks.filter((check) => !freeIds.has(check.id)) ?? [];

  return (
    <div className="relative flex min-h-full flex-1 flex-col overflow-hidden bg-background text-foreground">
      <div className="pointer-events-none absolute inset-x-0 top-0 h-80 bg-[radial-gradient(ellipse_at_top,rgba(220,38,38,0.16),transparent_58%)]" />
      <main className="relative mx-auto flex w-full max-w-3xl flex-col gap-10 px-5 py-16 sm:px-8 sm:py-20">
        <header className="flex flex-col gap-4">
          <p className="text-xs font-medium tracking-[0.22em] text-accent uppercase">
            Domain hygiene
          </p>
          <div className="flex flex-col gap-3">
            <h1 className="max-w-xl text-4xl font-semibold tracking-tight text-white sm:text-5xl">
              Domain & email security audit
            </h1>
            <p className="max-w-xl text-base leading-7 text-zinc-400">
              A stateless check of SPF, DMARC, HTTPS, and the response headers on the public site.
            </p>
          </div>
        </header>

        <form onSubmit={onSubmit} className="flex flex-col gap-3 sm:flex-row">
          <label htmlFor={inputId} className="sr-only">
            Domain
          </label>
          <input
            id={inputId}
            value={domain}
            onChange={(event) => setDomain(event.target.value)}
            placeholder="example.com"
            autoCapitalize="none"
            autoCorrect="off"
            spellCheck={false}
            inputMode="url"
            maxLength={2048}
            className="h-14 min-w-0 flex-1 rounded-md border border-line bg-card px-4 font-mono text-base text-white outline-none placeholder:text-zinc-500 focus:border-accent"
          />
          <button
            type="submit"
            disabled={loading || domain.trim().length === 0}
            className={`h-14 shrink-0 rounded-md bg-white px-5 text-sm font-semibold text-black transition hover:bg-zinc-200 disabled:cursor-not-allowed disabled:bg-white/40 ${loading ? "ring-1 ring-accent" : ""}`}
          >
            {loading ? "Scanning…" : "Run Free Security Audit"}
          </button>
        </form>

        {error ? (
          <p
            role="alert"
            className="rounded-md border border-accent/50 bg-accent/10 px-4 py-3 text-sm leading-6 text-white"
          >
            {error}
          </p>
        ) : null}

        {report ? (
          <section ref={resultsRef} aria-live="polite" className="flex flex-col gap-6">
            <div className="flex items-center gap-5 rounded-md border border-line bg-card p-5 sm:p-6">
              <div
                className={`flex h-24 w-24 shrink-0 items-center justify-center rounded-md border text-5xl font-semibold tracking-tight ${GRADE_STYLE[report.grade]}`}
                aria-label={`Grade ${report.grade}`}
              >
                {report.grade}
              </div>
              <div className="min-w-0">
                <p className="text-sm tracking-[0.16em] text-accent uppercase">Score</p>
                <p className="text-3xl font-semibold tracking-tight text-white tabular-nums">
                  {report.score}
                  <span className="text-lg font-medium text-zinc-500"> / 100</span>
                </p>
                <p className="mt-1 truncate font-mono text-sm text-zinc-300">{report.domain}</p>
                <p className="text-xs text-zinc-500">Scanned {formatWhen(report.scannedAt)}</p>
              </div>
            </div>

            {free.length > 0 ? (
              <div className="flex flex-col gap-3">
                <h2 className="text-sm font-medium text-zinc-300">Included in the free audit</h2>
                {free.map((check) => (
                  <CheckCard key={check.id} check={check} />
                ))}
              </div>
            ) : (
              <p className="text-sm leading-6 text-zinc-400">
                Every check passed. The line-by-line record stays in the locked preview.
              </p>
            )}

            <div className="flex flex-col gap-4 rounded-md border border-line bg-card p-5 shadow-[inset_2px_0_0_#DC2626] sm:flex-row sm:items-center sm:justify-between sm:p-6">
              <p className="max-w-xl text-sm leading-6 font-medium text-white">
                Unlock Full Plain-English Fix Guide & Copy-Paste DNS/Server Configs — $9
              </p>
              <button
                type="button"
                onClick={() => setUnlockOpen(true)}
                className="h-11 shrink-0 rounded-md bg-white px-4 text-sm font-semibold text-black transition hover:bg-zinc-200"
              >
                Unlock for $9
              </button>
            </div>

            {locked.length > 0 ? (
              <div className="flex flex-col gap-3">
                <h2 className="text-sm font-medium text-zinc-500">Locked preview</h2>
                <div className="grid gap-3 sm:grid-cols-2">
                  {locked.map((check) => (
                    <LockedCard key={check.id} check={check} />
                  ))}
                </div>
              </div>
            ) : null}
          </section>
        ) : null}

        <p className="text-xs leading-5 text-zinc-600">
          Nothing is stored. Each scan runs once and the result stays in this browser.
        </p>
      </main>

      <footer className="mt-auto border-t border-line px-5 py-6 text-center text-xs text-zinc-500">
        Built by DriftLogic — Stateless Domain & Email Security Diagnostics.
      </footer>

      <dialog
        ref={dialogRef}
        aria-labelledby={titleId}
        onClose={() => setUnlockOpen(false)}
        onClick={(event) => {
          if (event.target === event.currentTarget) setUnlockOpen(false);
        }}
        className="m-auto w-[min(28rem,calc(100%-2rem))] rounded-md border border-line bg-card p-6 text-foreground shadow-2xl backdrop:bg-black/80"
      >
        <h2 id={titleId} className="text-xl font-semibold tracking-tight text-white">
          Full fix guide
        </h2>
        <p className="mt-3 text-sm leading-6 text-zinc-400">
          Payment is not connected yet. When it is, $9 unlocks the plain-English fix guide and
          copy-paste DNS and server configs for every check.
        </p>
        <div className="mt-6 flex justify-end">
          <button
            type="button"
            onClick={() => setUnlockOpen(false)}
            className="h-10 rounded-md bg-white px-4 text-sm font-semibold text-black"
          >
            Close
          </button>
        </div>
      </dialog>
    </div>
  );
}

function CheckCard({ check }: { check: ScanCheck }) {
  return (
    <article className="rounded-md border border-line bg-card p-5">
      <div className="flex items-start justify-between gap-4">
        <div>
          <p className="text-xs tracking-[0.16em] text-zinc-500 uppercase">{check.category}</p>
          <h3 className="mt-1 text-lg font-semibold text-white">{check.title}</h3>
        </div>
        <StatusPill status={check.status} />
      </div>
      <p className="mt-3 text-sm leading-6 text-zinc-300">{check.impactSummary}</p>
      {check.rawValue ? (
        <pre className="mt-4 overflow-x-auto rounded-md border border-line bg-background p-3 font-mono text-xs leading-5 break-all whitespace-pre-wrap text-zinc-300">
          {check.rawValue}
        </pre>
      ) : (
        <p className="mt-4 text-xs text-zinc-500">No record returned.</p>
      )}
    </article>
  );
}

function LockedCard({ check }: { check: ScanCheck }) {
  return (
    <article className="relative overflow-hidden rounded-md border border-line bg-card">
      <div className="pointer-events-none blur-[6px] select-none" aria-hidden="true">
        <CheckCard check={check} />
      </div>
      <div className="absolute inset-0 flex items-center justify-center">
        <span className="rounded-md border border-accent/70 bg-background/90 px-3 py-1 text-xs font-medium tracking-[0.14em] text-accent uppercase">
          Locked
        </span>
      </div>
    </article>
  );
}

function StatusPill({ status }: { status: CheckStatus }) {
  return (
    <span className={`rounded-md px-2.5 py-1 text-xs font-medium tracking-wide uppercase ${STATUS_STYLE[status]}`}>
      {STATUS_LABEL[status]}
    </span>
  );
}

function rankIssues(checks: ScanCheck[]): ScanCheck[] {
  return checks
    .map((check, index) => ({ check, index }))
    .filter(({ check }) => check.status !== "pass")
    .sort(
      (left, right) =>
        STATUS_RANK[left.check.status] - STATUS_RANK[right.check.status] || left.index - right.index,
    )
    .slice(0, 2)
    .map(({ check }) => check);
}

function formatWhen(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(date);
}

function readError(payload: unknown, status: number): string {
  if (payload && typeof payload === "object" && "error" in payload && typeof payload.error === "string") {
    return payload.error;
  }
  if (status === 504) return "The scan timed out.";
  if (status === 400) return "Enter a public domain like example.com.";
  return "The scan could not be completed.";
}

function isReport(value: unknown): value is ScanReport {
  if (!value || typeof value !== "object") return false;
  const report = value as ScanReport;
  return (
    typeof report.domain === "string" &&
    typeof report.score === "number" &&
    (report.grade === "A" ||
      report.grade === "B" ||
      report.grade === "C" ||
      report.grade === "D" ||
      report.grade === "F") &&
    typeof report.scannedAt === "string" &&
    Array.isArray(report.checks)
  );
}
