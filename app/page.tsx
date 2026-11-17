"use client";

import { useEffect, useId, useRef, useState, type FormEvent } from "react";
import type { CheckStatus, Grade, ScanCheck, ScanReport } from "@/lib/scanner";

const STATUS_RANK: Record<CheckStatus, number> = { fail: 0, warn: 1, pass: 2 };

const GRADE_STYLE: Record<Grade, string> = {
  A: "border-emerald-300/40 bg-emerald-300/10 text-emerald-100",
  B: "border-lime-300/40 bg-lime-300/10 text-lime-100",
  C: "border-amber-300/40 bg-amber-300/10 text-amber-50",
  D: "border-orange-300/40 bg-orange-300/10 text-orange-50",
  F: "border-rose-300/40 bg-rose-300/10 text-rose-50",
};

const STATUS_STYLE: Record<CheckStatus, string> = {
  pass: "bg-emerald-300/15 text-emerald-100",
  warn: "bg-amber-300/15 text-amber-50",
  fail: "bg-rose-300/15 text-rose-50",
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
    <div className="relative min-h-full flex-1 overflow-hidden bg-[#090b10] text-zinc-100">
      <div className="pointer-events-none absolute inset-x-0 top-0 h-80 bg-[radial-gradient(ellipse_at_top,rgba(167,243,208,0.14),transparent_62%)]" />
      <main className="relative mx-auto flex w-full max-w-3xl flex-col gap-10 px-5 py-16 sm:px-8 sm:py-20">
        <header className="flex flex-col gap-4">
          <p className="text-xs font-medium tracking-[0.22em] text-emerald-200/80 uppercase">
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
            className="h-14 min-w-0 flex-1 rounded-2xl border border-white/10 bg-white/[0.04] px-4 font-mono text-base text-white outline-none placeholder:text-zinc-500 focus:border-emerald-200/50"
          />
          <button
            type="submit"
            disabled={loading || domain.trim().length === 0}
            className="h-14 shrink-0 rounded-2xl bg-white px-5 text-sm font-semibold text-zinc-950 transition hover:bg-zinc-200 disabled:cursor-not-allowed disabled:bg-white/40"
          >
            {loading ? "Scanning…" : "Run Free Security Audit"}
          </button>
        </form>

        {error ? (
          <p
            role="alert"
            className="rounded-2xl border border-rose-300/30 bg-rose-300/10 px-4 py-3 text-sm leading-6 text-rose-50"
          >
            {error}
          </p>
        ) : null}

        {report ? (
          <section ref={resultsRef} aria-live="polite" className="flex flex-col gap-6">
            <div className="flex items-center gap-5 rounded-3xl border border-white/10 bg-white/[0.03] p-5 sm:p-6">
              <div
                className={`flex h-24 w-24 shrink-0 items-center justify-center rounded-3xl border text-5xl font-semibold tracking-tight ${GRADE_STYLE[report.grade]}`}
                aria-label={`Grade ${report.grade}`}
              >
                {report.grade}
              </div>
              <div className="min-w-0">
                <p className="text-sm text-zinc-400">Score</p>
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

            <div className="flex flex-col gap-4 rounded-3xl border border-emerald-200/20 bg-emerald-200/[0.06] p-5 sm:flex-row sm:items-center sm:justify-between sm:p-6">
              <p className="max-w-xl text-sm leading-6 font-medium text-emerald-50">
                Unlock Full Plain-English Fix Guide & Copy-Paste DNS/Server Configs — $9
              </p>
              <button
                type="button"
                onClick={() => setUnlockOpen(true)}
                className="h-11 shrink-0 rounded-full bg-emerald-200 px-4 text-sm font-semibold text-emerald-950 transition hover:bg-emerald-100"
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

      <dialog
        ref={dialogRef}
        aria-labelledby={titleId}
        onClose={() => setUnlockOpen(false)}
        onClick={(event) => {
          if (event.target === event.currentTarget) setUnlockOpen(false);
        }}
        className="m-auto w-[min(28rem,calc(100%-2rem))] rounded-3xl border border-white/10 bg-[#10141c] p-6 text-zinc-100 shadow-2xl backdrop:bg-black/70"
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
            className="h-10 rounded-full bg-white px-4 text-sm font-semibold text-zinc-950"
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
    <article className="rounded-3xl border border-white/10 bg-white/[0.03] p-5">
      <div className="flex items-start justify-between gap-4">
        <div>
          <p className="text-xs tracking-[0.16em] text-zinc-500 uppercase">{check.category}</p>
          <h3 className="mt-1 text-lg font-semibold text-white">{check.title}</h3>
        </div>
        <StatusPill status={check.status} />
      </div>
      <p className="mt-3 text-sm leading-6 text-zinc-300">{check.impactSummary}</p>
      {check.rawValue ? (
        <pre className="mt-4 overflow-x-auto rounded-2xl bg-black/40 p-3 font-mono text-xs leading-5 break-all whitespace-pre-wrap text-zinc-300">
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
    <article className="relative overflow-hidden rounded-3xl border border-white/10 bg-white/[0.03]">
      <div className="pointer-events-none blur-[6px] select-none" aria-hidden="true">
        <CheckCard check={check} />
      </div>
      <div className="absolute inset-0 flex items-center justify-center">
        <span className="rounded-full border border-white/15 bg-[#090b10]/80 px-3 py-1 text-xs font-medium text-zinc-200">
          Locked
        </span>
      </div>
    </article>
  );
}

function StatusPill({ status }: { status: CheckStatus }) {
  return (
    <span className={`rounded-full px-2.5 py-1 text-xs font-medium ${STATUS_STYLE[status]}`}>
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
