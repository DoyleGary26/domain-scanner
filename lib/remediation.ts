import type { ScanCheck, ScanReport } from "@/lib/scanner";

export type FixSection = {
  title: string;
  explanation: string;
  config: string;
};

export type FixGuide = {
  summary: string;
  sections: FixSection[];
};

const GEMINI_URL =
  "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent";
const GEMINI_TIMEOUT_MS = 20_000;

export async function buildFixGuide(report: ScanReport): Promise<FixGuide> {
  const issues = report.checks.filter((check) => check.status === "fail" || check.status === "warn");
  const fallback = fallbackGuide(report.domain, issues);
  const apiKey = process.env.GEMINI_API_KEY?.trim();
  if (!apiKey || issues.length === 0) return fallback;

  try {
    const generated = await requestGeminiGuide(apiKey, report.domain, issues);
    return generated ?? fallback;
  } catch (error) {
    console.error("Gemini remediation failed; using the built-in guide.");
    if (error instanceof Error) console.error(error.message);
    return fallback;
  }
}

async function requestGeminiGuide(
  apiKey: string,
  domain: string,
  issues: ScanCheck[],
): Promise<FixGuide | null> {
  const endpoint = new URL(GEMINI_URL);
  endpoint.searchParams.set("key", apiKey);

  const response = await fetch(endpoint, {
    method: "POST",
    headers: { "content-type": "application/json" },
    cache: "no-store",
    signal: AbortSignal.timeout(GEMINI_TIMEOUT_MS),
    body: JSON.stringify({
      contents: [{ role: "user", parts: [{ text: remediationPrompt(domain, issues) }] }],
      generationConfig: {
        temperature: 0.2,
        responseMimeType: "application/json",
      },
    }),
  });

  if (!response.ok) return null;
  const payload: unknown = await response.json();
  const text = geminiText(payload);
  if (!text) return null;
  return parseGuide(text);
}

function remediationPrompt(domain: string, issues: ScanCheck[]): string {
  const findings = issues
    .map((check) => {
      const observed = (check.rawValue ?? "none").slice(0, 500);
      return `- ${check.title} (${check.status}): ${check.impactSummary} Observed: ${observed}`;
    })
    .join("\n");

  return [
    "Write a plain-English remediation guide for these domain and email security findings.",
    `Domain: ${domain}`,
    "Findings:",
    findings,
    "",
    "Return only JSON with this shape:",
    '{"summary":"2-4 sentences a site owner can act on","sections":[{"title":"short title","explanation":"what is wrong and the exact change to make","config":"copy-paste DNS record or web server header config"}]}',
    "",
    "Rules:",
    "- One section per finding, in the same order.",
    "- DNS records must be ready to paste and must use this domain.",
    "- Header configs must include an nginx add_header line and an Apache Header set line.",
    "- For SPF, keep existing mechanisms and end the record with -all. If the record is missing, publish v=spf1 -all and say to add include: mechanisms for real senders first.",
    "- For DMARC, use p=quarantine when the policy is missing or p=none.",
    "- Give only defensive DNS and response-header configuration. No exploit steps.",
  ].join("\n");
}

function geminiText(payload: unknown): string | null {
  if (!payload || typeof payload !== "object" || !("candidates" in payload)) return null;
  const candidates = payload.candidates;
  if (!Array.isArray(candidates)) return null;
  const first = candidates[0];
  if (!first || typeof first !== "object" || !("content" in first)) return null;
  const content = first.content;
  if (!content || typeof content !== "object" || !("parts" in content)) return null;
  const parts = content.parts;
  if (!Array.isArray(parts)) return null;
  const texts = parts
    .map((part) => (part && typeof part === "object" && "text" in part && typeof part.text === "string" ? part.text : ""))
    .filter(Boolean);
  return texts.join("\n").trim() || null;
}

function parseGuide(text: string): FixGuide | null {
  const fenced = text.replace(/^```(?:json)?\s*/i, "").replace(/\s*```$/, "").trim();
  const start = fenced.indexOf("{");
  const end = fenced.lastIndexOf("}");
  if (start === -1 || end <= start) return null;

  let parsed: unknown;
  try {
    parsed = JSON.parse(fenced.slice(start, end + 1));
  } catch {
    return null;
  }
  if (!parsed || typeof parsed !== "object") return null;
  const summary = "summary" in parsed && typeof parsed.summary === "string" ? parsed.summary.trim() : "";
  const rawSections = "sections" in parsed && Array.isArray(parsed.sections) ? parsed.sections : null;
  if (!summary || !rawSections) return null;

  const sections: FixSection[] = [];
  for (const item of rawSections.slice(0, 12)) {
    if (!item || typeof item !== "object") return null;
    const title = "title" in item && typeof item.title === "string" ? item.title.trim() : "";
    const explanation =
      "explanation" in item && typeof item.explanation === "string" ? item.explanation.trim() : "";
    const config = "config" in item && typeof item.config === "string" ? item.config.trim() : "";
    if (!title || !explanation || !config || config.length > 4000) return null;
    sections.push({ title, explanation, config });
  }
  if (sections.length === 0) return null;
  return { summary, sections };
}

function fallbackGuide(domain: string, issues: ScanCheck[]): FixGuide {
  if (issues.length === 0) {
    return {
      summary: `${domain} has no failing or warning checks. No DNS or header changes are required.`,
      sections: [],
    };
  }

  return {
    summary: `Apply these records and response headers for ${domain}. Publish DNS at the zone that serves ${domain}, then send the header lines from the HTTPS site that answers for that name.`,
    sections: issues.map((check) => fallbackSection(domain, check)),
  };
}

function fallbackSection(domain: string, check: ScanCheck): FixSection {
  switch (check.id) {
    case "spf":
      return {
        title: "SPF",
        explanation:
          "Publish one SPF TXT record on the root domain. List every service that sends mail for this domain, then end the record with -all so other servers are rejected.",
        config: spfRecord(domain, check.rawValue),
      };
    case "dmarc":
      return {
        title: "DMARC",
        explanation:
          "Publish a DMARC TXT record on _dmarc. Start with quarantine so failing mail is held, and send aggregate reports to a mailbox you read.",
        config: dmarcRecord(domain, check.rawValue),
      };
    case "https-enforcement":
      return {
        title: "HTTPS redirect",
        explanation:
          "Answer plain HTTP with a permanent redirect to the same host on HTTPS. Use 301 so browsers and scanners treat HTTPS as the only location.",
        config: httpsRedirect(domain),
      };
    case "hsts":
      return {
        title: "Strict-Transport-Security",
        explanation:
          "Send HSTS on HTTPS responses so browsers keep using HTTPS for this host. Add includeSubDomains only after every subdomain serves HTTPS.",
        config: headerPair(
          'add_header Strict-Transport-Security "max-age=15552000; includeSubDomains" always;',
          'Header always set Strict-Transport-Security "max-age=15552000; includeSubDomains"',
        ),
      };
    case "csp":
      return {
        title: "Content-Security-Policy",
        explanation:
          "Send a Content-Security-Policy that allows this site's own assets and blocks framing by other origins. Widen script-src only for hosts you actually use.",
        config: headerPair(
          `add_header Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'" always;`,
          `Header always set Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'"`,
        ),
      };
    case "x-frame-options":
      return {
        title: "X-Frame-Options",
        explanation: "Send X-Frame-Options so other sites cannot embed this origin in a frame.",
        config: headerPair(
          'add_header X-Frame-Options "DENY" always;',
          'Header always set X-Frame-Options "DENY"',
        ),
      };
    case "x-content-type-options":
      return {
        title: "X-Content-Type-Options",
        explanation: "Send nosniff so browsers use the declared content type instead of guessing one.",
        config: headerPair(
          'add_header X-Content-Type-Options "nosniff" always;',
          'Header always set X-Content-Type-Options "nosniff"',
        ),
      };
    case "referrer-policy":
      return {
        title: "Referrer-Policy",
        explanation:
          "Send a referrer policy that keeps the origin on cross-site requests and drops the path and query string.",
        config: headerPair(
          'add_header Referrer-Policy "strict-origin-when-cross-origin" always;',
          'Header always set Referrer-Policy "strict-origin-when-cross-origin"',
        ),
      };
    default:
      return {
        title: check.title,
        explanation: check.impactSummary,
        config: check.rawValue ?? `${domain}: review this check and publish the missing control.`,
      };
  }
}

function spfRecord(domain: string, raw: string | null): string {
  const current = raw?.trim() ?? "";
  if (/^v=spf1\b/i.test(current)) {
    const withoutAll = current.replace(/\s+[+\-~?]?all\s*$/i, "").trim();
    return `${domain}. 3600 IN TXT "${withoutAll} -all"`;
  }
  return [
    `${domain}. 3600 IN TXT "v=spf1 -all"`,
    "",
    `Before publishing -all, add one include:, ip4:, or ip6: mechanism for each service that sends mail as ${domain}.`,
  ].join("\n");
}

function dmarcRecord(domain: string, raw: string | null): string {
  const current = raw?.trim() ?? "";
  if (/^v=DMARC1\b/i.test(current)) {
    const policy = /\bp\s*=\s*none\b/i.test(current)
      ? current.replace(/\bp\s*=\s*none\b/i, "p=quarantine")
      : current;
    return `_dmarc.${domain}. 3600 IN TXT "${policy}"`;
  }
  return `_dmarc.${domain}. 3600 IN TXT "v=DMARC1; p=quarantine; rua=mailto:dmarc@${domain}; adkim=s; aspf=s"`;
}

function httpsRedirect(domain: string): string {
  return [
    "nginx",
    "server {",
    "  listen 80;",
    `  server_name ${domain};`,
    "  return 301 https://$host$request_uri;",
    "}",
    "",
    "Apache",
    "<VirtualHost *:80>",
    `  ServerName ${domain}`,
    "  Redirect permanent / https://%{HTTP_HOST}/",
    "</VirtualHost>",
  ].join("\n");
}

function headerPair(nginx: string, apache: string): string {
  return ["nginx", nginx, "", "Apache", apache].join("\n");
}
