import { ScanError, scanDomain, type CheckStatus, type ScanCheck, type ScanReport } from "@/lib/scanner";

const STATUS_RANK: Record<CheckStatus, number> = { fail: 0, warn: 1, pass: 2 };
const FREE_CHECK_LIMIT = 2;

export async function POST(request: Request) {
  const length = Number(request.headers.get("content-length") ?? "0");
  if (Number.isFinite(length) && length > 8192) {
    return Response.json({ error: "Request body is too large." }, { status: 400 });
  }

  let payload: unknown;
  try {
    payload = await request.json();
  } catch {
    return Response.json({ error: "Request body must be JSON." }, { status: 400 });
  }

  const domain = readDomain(payload);
  if (domain === null) {
    return Response.json(
      { error: "Expected a JSON body with a domain string." },
      { status: 400 },
    );
  }

  try {
    const report = await scanDomain(domain);
    return Response.json(gateReport(report), {
      headers: { "cache-control": "no-store" },
    });
  } catch (error) {
    if (error instanceof ScanError) {
      return Response.json(
        { error: error.message, code: error.code },
        { status: error.status },
      );
    }
    console.error(error);
    return Response.json({ error: "The scan could not be completed." }, { status: 500 });
  }
}

function gateReport(report: ScanReport) {
  const unlocked = new Set(
    report.checks
      .map((check, index) => ({ check, index }))
      .filter(({ check }) => check.status !== "pass")
      .sort(
        (left, right) =>
          STATUS_RANK[left.check.status] - STATUS_RANK[right.check.status] || left.index - right.index,
      )
      .slice(0, FREE_CHECK_LIMIT)
      .map(({ check }) => check.id),
  );

  return {
    domain: report.domain,
    score: report.score,
    grade: report.grade,
    scannedAt: report.scannedAt,
    checks: report.checks.map((check) =>
      unlocked.has(check.id) ? openCheck(check) : lockedCheck(check),
    ),
  };
}

function openCheck(check: ScanCheck) {
  return {
    id: check.id,
    category: check.category,
    title: check.title,
    status: check.status,
    rawValue: check.rawValue,
    impactSummary: check.impactSummary,
  };
}

function lockedCheck(check: ScanCheck) {
  return {
    id: check.id,
    category: check.category,
    title: check.title,
    status: check.status,
    locked: true as const,
  };
}

function readDomain(payload: unknown): string | null {
  if (!payload || typeof payload !== "object" || !("domain" in payload)) return null;
  return typeof payload.domain === "string" ? payload.domain : null;
}
