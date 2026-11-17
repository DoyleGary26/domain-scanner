import { resolve4, resolve6, resolveTxt } from "node:dns/promises";
import { domainToASCII } from "node:url";

const SCAN_TIMEOUT_MS = 8000;
const MAX_REDIRECTS = 3;
const MAX_BODY_BYTES = 1_048_576;
const SPF_LOOKUP_LIMIT = 10;

const SCORE = {
  spf: { pass: 15, warn: 7 },
  dmarc: { pass: 15, warn: 7 },
  "https-enforcement": { pass: 15, warn: 8 },
  hsts: { pass: 15, warn: 7 },
  csp: { pass: 10, warn: 5 },
  "x-frame-options": { pass: 10, warn: 4 },
  "x-content-type-options": { pass: 10, warn: 4 },
  "referrer-policy": { pass: 10, warn: 5 },
} as const;

const PASS_TOTAL = Object.values(SCORE).reduce((sum, item) => sum + item.pass, 0);
if (PASS_TOTAL !== 100) {
  throw new Error("Scanner score weights must total 100.");
}

type CheckId = keyof typeof SCORE;

export type CheckStatus = "pass" | "warn" | "fail";
export type Grade = "A" | "B" | "C" | "D" | "F";

export type ScanCheck = {
  id: CheckId;
  category: string;
  title: string;
  status: CheckStatus;
  rawValue: string | null;
  impactSummary: string;
};

export type ScanReport = {
  domain: string;
  score: number;
  grade: Grade;
  scannedAt: string;
  checks: ScanCheck[];
};

export class ScanError extends Error {
  readonly status: 400 | 504;
  readonly code: "invalid_domain" | "blocked_target" | "timeout";

  constructor(
    message: string,
    status: 400 | 504,
    code: "invalid_domain" | "blocked_target" | "timeout",
  ) {
    super(message);
    this.name = "ScanError";
    this.status = status;
    this.code = code;
  }
}

const BLOCKED_MESSAGE =
  "That host is blocked. Localhost, IP addresses, and private networks cannot be scanned.";

const HOSTNAME_PATTERN =
  /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

const BLOCKED_SUFFIXES = [
  ".localhost",
  ".local",
  ".internal",
  ".localdomain",
  ".home",
  ".lan",
  ".intranet",
  ".arpa",
];

const BLOCKED_IPV4: ReadonlyArray<readonly [number, number]> = [
  [0x00000000, 8],
  [0x0a000000, 8],
  [0x64400000, 10],
  [0x7f000000, 8],
  [0xa9fe0000, 16],
  [0xac100000, 12],
  [0xc0000000, 24],
  [0xc0a80000, 16],
  [0xc6120000, 15],
  [0xe0000000, 4],
  [0xf0000000, 4],
];

const STRONG_REFERRER = new Set([
  "no-referrer",
  "same-origin",
  "strict-origin",
  "strict-origin-when-cross-origin",
]);

const KNOWN_REFERRER = new Set([
  ...STRONG_REFERRER,
  "no-referrer-when-downgrade",
  "origin",
  "origin-when-cross-origin",
  "unsafe-url",
]);

class HopBlockedError extends Error {
  constructor() {
    super("Redirect target is not a public host.");
    this.name = "HopBlockedError";
  }
}

class HopUnreachableError extends Error {
  constructor() {
    super("Host could not be resolved to a public address.");
    this.name = "HopUnreachableError";
  }
}

type AddressVerdict = "public" | "none" | "blocked" | "timeout" | "dns_error";

export async function validateScanDomain(rawInput: string): Promise<string> {
  const domain = normalizeDomain(rawInput);
  await assertPublicTarget(domain, AbortSignal.timeout(SCAN_TIMEOUT_MS));
  return domain;
}

export async function scanDomain(rawInput: string): Promise<ScanReport> {
  const domain = normalizeDomain(rawInput);
  const timeout = AbortSignal.timeout(SCAN_TIMEOUT_MS);
  const stop = new AbortController();
  const signal = AbortSignal.any([timeout, stop.signal]);

  try {
    const verdict = await assertPublicTarget(domain, signal);
    const httpEnabled = verdict === "public";
    const spfPromise = checkSpf(domain, signal);
    const dmarcPromise = checkDmarc(domain, signal);
    const httpsPromise = checkHttps(domain, signal, httpEnabled);
    const headerPromise = checkHeaders(domain, signal, httpEnabled);
    for (const promise of [spfPromise, dmarcPromise, httpsPromise, headerPromise]) {
      promise.catch(() => undefined);
    }

    const [spf, dmarc, https, headers] = await Promise.all([
      spfPromise,
      dmarcPromise,
      httpsPromise,
      headerPromise,
    ]);
    const checks = [spf, dmarc, https, ...headers];
    const score = scoreChecks(checks);

    return {
      domain,
      score,
      grade: gradeFor(score),
      scannedAt: new Date().toISOString(),
      checks,
    };
  } catch (error) {
    if (error instanceof ScanError) throw error;
    if (isTimeoutError(error)) {
      throw new ScanError("The scan timed out.", 504, "timeout");
    }
    throw error;
  } finally {
    stop.abort();
  }
}

async function assertPublicTarget(domain: string, signal: AbortSignal): Promise<AddressVerdict> {
  const verdict = await addressVerdict(domain, signal);
  if (verdict === "timeout") {
    throw new ScanError("The scan timed out.", 504, "timeout");
  }
  if (verdict === "blocked") {
    throw new ScanError(BLOCKED_MESSAGE, 400, "blocked_target");
  }
  if (verdict === "dns_error") {
    throw new ScanError(
      "Could not verify that this domain points at a public address.",
      400,
      "invalid_domain",
    );
  }
  return verdict;
}

function normalizeDomain(rawInput: string): string {
  const trimmed = rawInput.trim();
  if (!trimmed) {
    throw new ScanError("Enter a domain name.", 400, "invalid_domain");
  }
  if (trimmed.length > 2048) {
    throw new ScanError("Enter a public domain like example.com.", 400, "invalid_domain");
  }

  const candidate = trimmed.startsWith("//")
    ? `http:${trimmed}`
    : /^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed)
      ? trimmed
      : `http://${trimmed}`;

  let url: URL;
  try {
    url = new URL(candidate);
  } catch {
    throw new ScanError("Enter a public domain like example.com.", 400, "invalid_domain");
  }

  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new ScanError("Enter a public domain like example.com.", 400, "invalid_domain");
  }

  const host = canonicalHost(url.hostname);
  if (!host || isIpLiteral(host) || isBlockedHostname(host)) {
    throw new ScanError(BLOCKED_MESSAGE, 400, "blocked_target");
  }
  if (!HOSTNAME_PATTERN.test(host)) {
    throw new ScanError("Enter a public domain like example.com.", 400, "invalid_domain");
  }
  return host;
}

function canonicalHost(hostname: string): string {
  const stripped = stripBrackets(hostname).trim().toLowerCase().replace(/\.+$/, "");
  if (!stripped) return "";
  const ascii = domainToASCII(stripped).toLowerCase().replace(/\.+$/, "");
  return ascii;
}

function stripBrackets(hostname: string): string {
  if (hostname.startsWith("[") && hostname.endsWith("]") && hostname.length > 2) {
    return hostname.slice(1, -1);
  }
  return hostname;
}

function isBlockedHostname(host: string): boolean {
  if (
    host === "localhost" ||
    host.endsWith(".localhost") ||
    host === "0" ||
    host === "broadcasthost"
  ) {
    return true;
  }
  return BLOCKED_SUFFIXES.some(
    (suffix) => host === suffix.slice(1) || host.endsWith(suffix),
  );
}

function isIpLiteral(host: string): boolean {
  if (host.includes(":")) return true;
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)) return true;
  if (/^(?:\d+\.)*\d+$/.test(host)) return true;
  return false;
}

async function addressVerdict(hostname: string, signal: AbortSignal): Promise<AddressVerdict> {
  const host = canonicalHost(hostname);
  if (!host || isIpLiteral(host) || isBlockedHostname(host)) return "blocked";
  if (signal.aborted) return "timeout";

  try {
    const addresses = await lookupAddresses(host, signal);
    if (addresses.length === 0) return "none";
    if (addresses.some((address) => isNonPublicIp(address))) return "blocked";
    return "public";
  } catch (error) {
    if (isTimeoutError(error)) return "timeout";
    return "dns_error";
  }
}

async function lookupAddresses(hostname: string, signal: AbortSignal): Promise<string[]> {
  const [v4, v6] = await Promise.all([
    resolveFamily(resolve4, hostname, signal),
    resolveFamily(resolve6, hostname, signal),
  ]);
  return [...v4, ...v6];
}

async function resolveFamily(
  lookup: (hostname: string) => Promise<string[]>,
  hostname: string,
  signal: AbortSignal,
): Promise<string[]> {
  try {
    return await withSignal(lookup(hostname), signal);
  } catch (error) {
    if (isTimeoutError(error)) throw error;
    const code = errorCode(error);
    if (code === "ENOTFOUND" || code === "ENODATA" || code === "ENOENT") return [];
    if (code === "EAI_AGAIN" || code === "ETIMEOUT") {
      throw timeoutError(signal);
    }
    throw error;
  }
}

async function readTxt(name: string, signal: AbortSignal): Promise<string[] | "error"> {
  try {
    const records = await withSignal(resolveTxt(name), signal);
    return records.map((parts) => parts.join("").trim()).filter(Boolean);
  } catch (error) {
    if (isTimeoutError(error)) throw new ScanError("The scan timed out.", 504, "timeout");
    const code = errorCode(error);
    if (code === "ENOTFOUND" || code === "ENODATA" || code === "ENOENT") return [];
    if (code === "EAI_AGAIN" || code === "ETIMEOUT") {
      throw new ScanError("The scan timed out.", 504, "timeout");
    }
    return "error";
  }
}

function withSignal<T>(promise: Promise<T>, signal: AbortSignal): Promise<T> {
  if (signal.aborted) return Promise.reject(timeoutError(signal));
  return new Promise<T>((resolve, reject) => {
    const onAbort = () => reject(timeoutError(signal));
    signal.addEventListener("abort", onAbort, { once: true });
    promise.then(
      (value) => {
        signal.removeEventListener("abort", onAbort);
        resolve(value);
      },
      (error: unknown) => {
        signal.removeEventListener("abort", onAbort);
        reject(error);
      },
    );
  });
}

async function checkSpf(domain: string, signal: AbortSignal): Promise<ScanCheck> {
  const records = await readTxt(domain, signal);
  if (records === "error") {
    return makeCheck(
      "spf",
      "Email",
      "SPF Record",
      "fail",
      null,
      "The TXT lookup failed, so receivers cannot see an SPF policy for this domain.",
    );
  }

  const spf = records.filter((record) => /^\s*v\s*=\s*spf1\b/i.test(record));
  if (spf.length === 0) {
    return makeCheck(
      "spf",
      "Email",
      "SPF Record",
      "fail",
      null,
      "No SPF record. Other servers can send mail that looks like it came from this domain.",
    );
  }
  if (spf.length > 1) {
    return makeCheck(
      "spf",
      "Email",
      "SPF Record",
      "warn",
      clip(spf.join(" | ")),
      "More than one SPF record is published, so receivers may ignore the policy.",
    );
  }

  const record = spf[0] ?? "";
  const lookups = countSpfDnsMechanisms(record);
  if (lookups > SPF_LOOKUP_LIMIT) {
    return makeCheck(
      "spf",
      "Email",
      "SPF Record",
      "warn",
      clip(record),
      `This SPF record uses ${lookups} DNS lookups, above the RFC 7208 limit of ${SPF_LOOKUP_LIMIT}, so receivers may reject the policy.`,
    );
  }
  const qualifier = firstAllQualifier(record);
  if (qualifier === "-" || qualifier === "~") {
    return makeCheck(
      "spf",
      "Email",
      "SPF Record",
      "pass",
      clip(record),
      qualifier === "-"
        ? "SPF ends in -all, so unlisted senders are rejected."
        : "SPF ends in ~all, so unlisted senders soft-fail.",
    );
  }
  if (qualifier === "+" || qualifier === "?") {
    const label = qualifier === "+" ? "+all" : "?all";
    return makeCheck(
      "spf",
      "Email",
      "SPF Record",
      "warn",
      clip(record),
      `SPF ends in ${label}, so receivers are not told to reject unlisted senders.`,
    );
  }
  return makeCheck(
    "spf",
    "Email",
    "SPF Record",
    "warn",
    clip(record),
    "SPF is published, but it never says what to do with senders that are not listed.",
  );
}

function countSpfDnsMechanisms(record: string): number {
  let count = 0;
  for (const term of record.trim().split(/\s+/)) {
    const bare = term.replace(/^[+\-~?]/, "").toLowerCase();
    if (
      bare.startsWith("include:") ||
      bare === "a" ||
      bare.startsWith("a:") ||
      bare.startsWith("a/") ||
      bare === "mx" ||
      bare.startsWith("mx:") ||
      bare.startsWith("mx/") ||
      bare === "ptr" ||
      bare.startsWith("ptr:") ||
      bare.startsWith("exists:") ||
      bare.startsWith("redirect=")
    ) {
      count += 1;
    }
  }
  return count;
}

function firstAllQualifier(record: string): "+" | "-" | "~" | "?" | null {
  const match = /(?:^|\s)([+~?-])?all(?=\s|$)/i.exec(record);
  if (!match) return null;
  const qualifier = match[1];
  if (qualifier === "-" || qualifier === "~" || qualifier === "?" || qualifier === "+") {
    return qualifier;
  }
  return "+";
}

async function checkDmarc(domain: string, signal: AbortSignal): Promise<ScanCheck> {
  const records = await readTxt(`_dmarc.${domain}`, signal);
  if (records === "error") {
    return makeCheck(
      "dmarc",
      "Email",
      "DMARC Record",
      "fail",
      null,
      "The TXT lookup for _dmarc failed, so receivers have no domain policy to read.",
    );
  }

  const dmarc = records.filter((record) => /^\s*v\s*=\s*DMARC1\b/i.test(record));
  if (dmarc.length === 0) {
    return makeCheck(
      "dmarc",
      "Email",
      "DMARC Record",
      "fail",
      null,
      "No DMARC record. Receivers have no policy for mail that spoofs this domain.",
    );
  }
  if (dmarc.length > 1) {
    return makeCheck(
      "dmarc",
      "Email",
      "DMARC Record",
      "warn",
      clip(dmarc.join(" | ")),
      "More than one DMARC record is published, so receivers may ignore the policy.",
    );
  }

  const record = dmarc[0] ?? "";
  const policy = tagValue(record, "p");
  if (policy === "reject" || policy === "quarantine") {
    return makeCheck(
      "dmarc",
      "Email",
      "DMARC Record",
      "pass",
      clip(record),
      `DMARC tells receivers to ${policy} mail that fails alignment.`,
    );
  }
  if (policy === "none" || policy === null) {
    return makeCheck(
      "dmarc",
      "Email",
      "DMARC Record",
      "warn",
      clip(record),
      policy === null
        ? "DMARC is published without p=, which defaults to none, so failing mail is still delivered."
        : "DMARC is published with p=none, so failing mail is delivered and spoofing is only monitored.",
    );
  }
  return makeCheck(
    "dmarc",
    "Email",
    "DMARC Record",
    "fail",
    clip(record),
    "DMARC is published with a policy receivers do not recognize.",
  );
}

function tagValue(record: string, name: string): string | null {
  for (const part of record.split(";")) {
    const separator = part.indexOf("=");
    if (separator === -1) continue;
    const key = part.slice(0, separator).trim().toLowerCase();
    if (key === name) return part.slice(separator + 1).trim().toLowerCase();
  }
  return null;
}

async function checkHttps(
  domain: string,
  signal: AbortSignal,
  enabled: boolean,
): Promise<ScanCheck> {
  if (!enabled) {
    return failedCheck(
      "https-enforcement",
      "Transport",
      "HTTPS Enforcement",
      "HTTPS enforcement could not be checked because this domain has no public address record.",
    );
  }
  try {
    const response = await publicFetch(new URL(`http://${domain}/`), signal, domain);
    const location = response.headers.get("location");
    const status = response.status;
    await readBoundedBody(response);
    return gradeHttps(domain, status, location);
  } catch (error) {
    if (error instanceof ScanError) throw error;
    if (isTimeoutError(error)) throw new ScanError("The scan timed out.", 504, "timeout");
    return failedCheck(
      "https-enforcement",
      "Transport",
      "HTTPS Enforcement",
      "The HTTP port did not respond, so no HTTPS redirect could be confirmed.",
    );
  }
}

function gradeHttps(domain: string, status: number, location: string | null): ScanCheck {
  const rawValue = clip(location ? `${status} ${location}` : String(status));
  let target: URL | null = null;
  if (location) {
    try {
      target = new URL(location, `http://${domain}/`);
    } catch {
      target = null;
    }
  }
  const sameSite = target ? isSameSiteHost(canonicalHost(target.hostname), domain) : false;
  const toHttps = target?.protocol === "https:";
  const permanent = status === 301 || status === 308;
  const temporary = status === 302 || status === 307;

  if (permanent && toHttps && sameSite) {
    return makeCheck(
      "https-enforcement",
      "Transport",
      "HTTPS Enforcement",
      "pass",
      rawValue,
      "HTTP visitors are permanently redirected to HTTPS on this hostname.",
    );
  }
  if (temporary && toHttps && sameSite) {
    return makeCheck(
      "https-enforcement",
      "Transport",
      "HTTPS Enforcement",
      "warn",
      rawValue,
      "HTTP visitors reach HTTPS through a temporary redirect. A 301 or 308 is the durable signal.",
    );
  }
  if (toHttps && !sameSite) {
    return makeCheck(
      "https-enforcement",
      "Transport",
      "HTTPS Enforcement",
      "fail",
      rawValue,
      "HTTP redirects to HTTPS on a different host, so this hostname is not pinned to HTTPS.",
    );
  }
  return makeCheck(
    "https-enforcement",
    "Transport",
    "HTTPS Enforcement",
    "fail",
    rawValue,
    "HTTP does not permanently redirect this hostname to HTTPS, so the first request can stay unencrypted.",
  );
}

function isSameSiteHost(host: string, domain: string): boolean {
  if (!host) return false;
  if (host === domain || host === `www.${domain}`) return true;
  return domain.startsWith("www.") && host === domain.slice(4);
}

async function checkHeaders(
  domain: string,
  signal: AbortSignal,
  enabled: boolean,
): Promise<ScanCheck[]> {
  if (!enabled) return headerResults(null, "the domain has no public address record");

  try {
    const response = await loadHttps(domain, signal);
    if (!response) return headerResults(null, "the HTTPS site did not respond");
    const checks = headerResults(response, null);
    await readBoundedBody(response);
    return checks;
  } catch (error) {
    if (error instanceof ScanError) throw error;
    if (isTimeoutError(error)) throw new ScanError("The scan timed out.", 504, "timeout");
    return headerResults(null, "the HTTPS site did not respond");
  }
}

async function loadHttps(domain: string, signal: AbortSignal): Promise<Response | null> {
  let current = new URL(`https://${domain}/`);
  let response: Response;
  try {
    response = await publicFetch(current, signal, domain);
  } catch (error) {
    if (error instanceof HopBlockedError || error instanceof HopUnreachableError) return null;
    throw error;
  }

  for (let followed = 0; followed < MAX_REDIRECTS; followed += 1) {
    if (response.status < 300 || response.status >= 400) return response;
    const location = response.headers.get("location");
    if (!location) return response;
    let target: URL;
    try {
      target = new URL(location, current);
    } catch {
      return response;
    }
    if (!isAllowedHttpUrl(target)) return response;

    let next: Response;
    try {
      next = await publicFetch(target, signal, domain);
    } catch (error) {
      if (error instanceof HopBlockedError || error instanceof HopUnreachableError) return response;
      await readBoundedBody(response);
      throw error;
    }
    await readBoundedBody(response);
    response = next;
    current = target;
  }
  return response;
}

async function readBoundedBody(response: Response): Promise<void> {
  const body = response.body;
  if (!body) return;
  const reader = body.getReader();
  let received = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) return;
      received += value.byteLength;
      if (received > MAX_BODY_BYTES) {
        await reader.cancel();
        return;
      }
    }
  } catch (error) {
    await reader.cancel().catch(() => undefined);
    if (isTimeoutError(error)) throw error;
  }
}

async function publicFetch(url: URL, signal: AbortSignal, originalDomain: string): Promise<Response> {
  if (!isAllowedHttpUrl(url)) throw new HopBlockedError();
  const verdict = await addressVerdict(url.hostname, signal);
  if (verdict === "timeout") throw new ScanError("The scan timed out.", 504, "timeout");
  if (verdict === "blocked") {
    if (canonicalHost(url.hostname) === originalDomain) {
      throw new ScanError(BLOCKED_MESSAGE, 400, "blocked_target");
    }
    throw new HopBlockedError();
  }
  if (verdict !== "public") throw new HopUnreachableError();

  return fetch(url, {
    redirect: "manual",
    signal,
    cache: "no-store",
    headers: {
      accept: "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
      "user-agent": "DomainHygieneScanner/1.0",
    },
  });
}

function isAllowedHttpUrl(url: URL): boolean {
  if (url.username || url.password) return false;
  if (url.protocol === "http:") return url.port === "" || url.port === "80";
  if (url.protocol === "https:") return url.port === "" || url.port === "443";
  return false;
}

function headerResults(response: Response | null, unavailable: string | null): ScanCheck[] {
  const read = (name: string) => {
    if (!response) return null;
    const value = response.headers.get(name);
    return value?.trim() ? value.trim() : null;
  };
  const csp = read("content-security-policy");
  const reportOnly = read("content-security-policy-report-only");
  return [
    gradeHsts(read("strict-transport-security"), unavailable),
    gradeCsp(csp, reportOnly, unavailable),
    gradeFrameOptions(read("x-frame-options"), csp, unavailable),
    gradeContentTypeOptions(read("x-content-type-options"), unavailable),
    gradeReferrerPolicy(read("referrer-policy"), unavailable),
  ];
}

function gradeHsts(raw: string | null, unavailable: string | null): ScanCheck {
  if (!raw) {
    return makeCheck(
      "hsts",
      "Headers",
      "Strict-Transport-Security",
      "fail",
      null,
      unavailable
        ? `Strict-Transport-Security was not observed because ${unavailable}.`
        : "No HSTS header. After this visit, a browser can still be sent back to HTTP.",
    );
  }
  const match = /max-age\s*=\s*"?(\d+)"?/i.exec(raw);
  if (!match) {
    return makeCheck(
      "hsts",
      "Headers",
      "Strict-Transport-Security",
      "fail",
      clip(raw),
      "HSTS is present but has no max-age, so browsers ignore it.",
    );
  }
  const maxAge = Number(match[1]);
  if (!Number.isFinite(maxAge) || maxAge <= 0) {
    return makeCheck(
      "hsts",
      "Headers",
      "Strict-Transport-Security",
      "fail",
      clip(raw),
      "HSTS max-age is zero, so browsers do not keep forcing HTTPS.",
    );
  }
  if (maxAge < 15_552_000) {
    return makeCheck(
      "hsts",
      "Headers",
      "Strict-Transport-Security",
      "warn",
      clip(raw),
      `HSTS max-age is ${maxAge} seconds, shorter than the six months a durable policy uses.`,
    );
  }
  return makeCheck(
    "hsts",
    "Headers",
    "Strict-Transport-Security",
    "pass",
    clip(raw),
    "HSTS lasts at least six months, so browsers keep using HTTPS after the first visit.",
  );
}

function gradeCsp(
  raw: string | null,
  reportOnly: string | null,
  unavailable: string | null,
): ScanCheck {
  if (!raw && reportOnly) {
    return makeCheck(
      "csp",
      "Headers",
      "Content-Security-Policy",
      "warn",
      clip(reportOnly),
      "CSP is report-only, so the browser records violations and does not block them.",
    );
  }
  if (!raw) {
    return makeCheck(
      "csp",
      "Headers",
      "Content-Security-Policy",
      "fail",
      null,
      unavailable
        ? `Content-Security-Policy was not observed because ${unavailable}.`
        : "No Content-Security-Policy. An injected script has nothing in the browser to stop it.",
    );
  }

  const directives = parseDirectives(raw);
  const sources = directives.get("script-src") ?? directives.get("default-src") ?? null;
  if (!sources) {
    return makeCheck(
      "csp",
      "Headers",
      "Content-Security-Policy",
      "warn",
      clip(raw),
      "CSP is present but does not set script-src or default-src, so script sources stay open.",
    );
  }
  if (sources.length === 0 || sources.some((token) => !isStrictSource(token))) {
    return makeCheck(
      "csp",
      "Headers",
      "Content-Security-Policy",
      "warn",
      clip(raw),
      "CSP still allows a broad or unsafe script source, so injected script may run.",
    );
  }
  return makeCheck(
    "csp",
    "Headers",
    "Content-Security-Policy",
    "pass",
    clip(raw),
    "CSP restricts script sources to this site, nonces, hashes, or named hosts.",
  );
}

function gradeFrameOptions(
  raw: string | null,
  csp: string | null,
  unavailable: string | null,
): ScanCheck {
  const value = raw?.split(",")[0]?.trim().toUpperCase() ?? "";
  if (value === "DENY" || value === "SAMEORIGIN") {
    return makeCheck(
      "x-frame-options",
      "Headers",
      "X-Frame-Options",
      "pass",
      clip(raw),
      value === "DENY"
        ? "The page refuses to be framed, which blocks clickjacking."
        : "The page can only be framed by itself, which blocks cross-site clickjacking.",
    );
  }

  const ancestors = csp ? parseDirectives(csp).get("frame-ancestors") : undefined;
  if (ancestors && ancestors.length > 0 && ancestors.every(isFrameSource)) {
    return makeCheck(
      "x-frame-options",
      "Headers",
      "X-Frame-Options",
      "pass",
      clip(`frame-ancestors ${ancestors.join(" ")}`),
      "CSP frame-ancestors limits who can embed this page, covering the same risk as X-Frame-Options.",
    );
  }
  if (value.startsWith("ALLOW-FROM") || (ancestors && ancestors.length > 0)) {
    return makeCheck(
      "x-frame-options",
      "Headers",
      "X-Frame-Options",
      "warn",
      clip(raw ?? (ancestors ? `frame-ancestors ${ancestors.join(" ")}` : null)),
      "Framing is only partly limited. ALLOW-FROM is obsolete, and a loose frame-ancestors list still lets other sites embed the page.",
    );
  }
  if (raw) {
    return makeCheck(
      "x-frame-options",
      "Headers",
      "X-Frame-Options",
      "warn",
      clip(raw),
      "X-Frame-Options is set to a value browsers do not treat as DENY or SAMEORIGIN.",
    );
  }
  return makeCheck(
    "x-frame-options",
    "Headers",
    "X-Frame-Options",
    "fail",
    null,
    unavailable
      ? `X-Frame-Options was not observed because ${unavailable}.`
      : "No framing control. Another site can embed this page and trick a click.",
  );
}

function gradeContentTypeOptions(raw: string | null, unavailable: string | null): ScanCheck {
  const token = raw?.split(",")[0]?.trim().toLowerCase() ?? "";
  if (token === "nosniff") {
    return makeCheck(
      "x-content-type-options",
      "Headers",
      "X-Content-Type-Options",
      "pass",
      clip(raw),
      "nosniff stops browsers from guessing a content type and executing a file as something else.",
    );
  }
  if (raw) {
    return makeCheck(
      "x-content-type-options",
      "Headers",
      "X-Content-Type-Options",
      "warn",
      clip(raw),
      "X-Content-Type-Options is present, but the value is not nosniff, so browsers can still sniff content types.",
    );
  }
  return makeCheck(
    "x-content-type-options",
    "Headers",
    "X-Content-Type-Options",
    "fail",
    null,
    unavailable
      ? `X-Content-Type-Options was not observed because ${unavailable}.`
      : "No nosniff header. Browsers may treat an uploaded or proxied file as a different content type.",
  );
}

function gradeReferrerPolicy(raw: string | null, unavailable: string | null): ScanCheck {
  if (!raw) {
    return makeCheck(
      "referrer-policy",
      "Headers",
      "Referrer-Policy",
      "fail",
      null,
      unavailable
        ? `Referrer-Policy was not observed because ${unavailable}.`
        : "No Referrer-Policy. Full URLs can leak to other sites in the Referer header.",
    );
  }
  const recognized = raw
    .split(",")
    .map((part) => part.trim().toLowerCase())
    .filter((part) => KNOWN_REFERRER.has(part));
  const effective = recognized.at(-1) ?? null;
  if (effective && STRONG_REFERRER.has(effective)) {
    return makeCheck(
      "referrer-policy",
      "Headers",
      "Referrer-Policy",
      "pass",
      clip(raw),
      `Referrer policy is ${effective}, so full URLs are not sent to other sites.`,
    );
  }
  return makeCheck(
    "referrer-policy",
    "Headers",
    "Referrer-Policy",
    "warn",
    clip(raw),
    effective
      ? `Referrer policy is ${effective}, which still shares part or all of the URL with other sites.`
      : "Referrer-Policy is present, but the value is not a policy browsers apply.",
  );
}

function parseDirectives(value: string): Map<string, string[]> {
  const directives = new Map<string, string[]>();
  for (const part of value.split(";")) {
    const tokens = part.trim().split(/\s+/).filter(Boolean);
    const name = tokens[0]?.toLowerCase();
    if (!name) continue;
    directives.set(
      name,
      tokens.slice(1).map((token) => token.toLowerCase()),
    );
  }
  return directives;
}

function isStrictSource(token: string): boolean {
  if (token === "'none'" || token === "'self'" || token === "'strict-dynamic'" || token === "'unsafe-hashes'") {
    return token !== "'unsafe-hashes'";
  }
  if (token.startsWith("'nonce-") || token.startsWith("'sha")) return true;
  return isHostSource(token);
}

function isFrameSource(token: string): boolean {
  return token === "'none'" || token === "'self'" || isHostSource(token);
}

function isHostSource(token: string): boolean {
  const host = token.replace(/^\*\./, "").replace(/:\d+$/, "");
  return /^[a-z0-9.-]+$/.test(host) && host.includes(".") && !host.startsWith(".") && !host.endsWith(".");
}

function failedCheck(
  id: CheckId,
  category: string,
  title: string,
  impactSummary: string,
): ScanCheck {
  return makeCheck(id, category, title, "fail", null, impactSummary);
}

function makeCheck(
  id: CheckId,
  category: string,
  title: string,
  status: CheckStatus,
  rawValue: string | null,
  impactSummary: string,
): ScanCheck {
  return { id, category, title, status, rawValue, impactSummary };
}

function scoreChecks(checks: ScanCheck[]): number {
  return checks.reduce((total, check) => {
    if (check.status === "fail") return total;
    return total + SCORE[check.id][check.status];
  }, 0);
}

function gradeFor(score: number): Grade {
  if (score >= 90) return "A";
  if (score >= 75) return "B";
  if (score >= 60) return "C";
  if (score >= 40) return "D";
  return "F";
}

function clip(value: string | null): string | null {
  if (!value) return null;
  const trimmed = value.trim();
  if (!trimmed) return null;
  return trimmed.length > 2000 ? `${trimmed.slice(0, 2000)}…` : trimmed;
}

function isNonPublicIp(ip: string): boolean {
  const address = ip.trim().toLowerCase();
  if (address.includes(":")) {
    const groups = expandIpv6(address);
    if (!groups) return true;
    return isNonPublicIpv6(groups);
  }
  const value = ipv4ToInt(address);
  if (value === null) return true;
  return isNonPublicIpv4(value);
}

function isNonPublicIpv4(ip: number): boolean {
  return BLOCKED_IPV4.some(([base, bits]) => {
    const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
    return ((ip & mask) >>> 0) === ((base & mask) >>> 0);
  });
}

function ipv4ToInt(ip: string): number | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  let value = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const octet = Number(part);
    if (!Number.isInteger(octet) || octet > 255) return null;
    value = (value * 256 + octet) >>> 0;
  }
  return value;
}

function expandIpv6(input: string): number[] | null {
  let address = input.toLowerCase().split("%")[0] ?? "";
  if (!address) return null;

  let mapped: [number, number] | null = null;
  if (address.includes(".")) {
    const lastColon = address.lastIndexOf(":");
    if (lastColon === -1) return null;
    const v4 = ipv4ToInt(address.slice(lastColon + 1));
    if (v4 === null) return null;
    mapped = [(v4 >>> 16) & 0xffff, v4 & 0xffff];
    address = address.slice(0, lastColon);
  }

  const halves = address.split("::");
  if (halves.length > 2) return null;
  const parseSide = (side: string) => {
    if (!side) return [];
    return side.split(":").map((part) => {
      if (!/^[0-9a-f]{1,4}$/.test(part)) return Number.NaN;
      return Number.parseInt(part, 16);
    });
  };
  const head = parseSide(halves[0] ?? "");
  const tail = halves.length === 2 ? parseSide(halves[1] ?? "") : [];
  if ([...head, ...tail].some((part) => Number.isNaN(part))) return null;

  const width = mapped ? 6 : 8;
  if (halves.length === 1) {
    if (head.length !== width) return null;
    return mapped ? [...head, ...mapped] : head;
  }
  const fill = width - head.length - tail.length;
  if (fill < 0) return null;
  const groups = [...head, ...Array<number>(fill).fill(0), ...tail];
  return mapped ? [...groups, ...mapped] : groups;
}

function isNonPublicIpv6(groups: number[]): boolean {
  if (groups.length !== 8) return true;
  const [g0, g1, g2, g3, g4, g5, g6, g7] = groups;
  if (groups.every((part) => part === 0)) return true;
  if (groups.slice(0, 7).every((part) => part === 0) && g7 === 1) return true;
  if ((g0 & 0xfe00) === 0xfc00) return true;
  if ((g0 & 0xffc0) === 0xfe80) return true;
  if ((g0 & 0xffc0) === 0xfec0) return true;
  if ((g0 & 0xff00) === 0xff00) return true;
  if (isIpv4Mapped(g0, g1, g2, g3, g4, g5)) {
    return isNonPublicIpv4(((g6 << 16) | g7) >>> 0);
  }
  const nat64 = g0 === 0x64 && g1 === 0xff9b && g2 === 0 && g3 === 0 && g4 === 0 && g5 === 0;
  if (nat64) return isNonPublicIpv4(((g6 << 16) | g7) >>> 0);
  return false;
}

function isIpv4Mapped(g0: number, g1: number, g2: number, g3: number, g4: number, g5: number): boolean {
  return g0 === 0 && g1 === 0 && g2 === 0 && g3 === 0 && g4 === 0 && g5 === 0xffff;
}

function isTimeoutError(error: unknown): boolean {
  if (!error || typeof error !== "object") return false;
  const name = "name" in error ? String(error.name) : "";
  const code = errorCode(error);
  return (
    name === "TimeoutError" ||
    name === "AbortError" ||
    code === "ABORT_ERR" ||
    code === "ETIMEOUT" ||
    code === "EAI_AGAIN" ||
    code === "UND_ERR_CONNECT_TIMEOUT" ||
    code === "UND_ERR_HEADERS_TIMEOUT" ||
    code === "UND_ERR_BODY_TIMEOUT"
  );
}

function timeoutError(signal: AbortSignal): Error {
  if (signal.reason instanceof Error) return signal.reason;
  const error = new Error("The operation timed out.");
  error.name = "TimeoutError";
  return error;
}

function errorCode(error: unknown): string {
  if (!error || typeof error !== "object" || !("code" in error)) return "";
  return String(error.code);
}
