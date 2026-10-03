const MARKER = "[REDACTED]";
const MARKER_SPLIT = /(\[REDACTED(?::[a-z-]{1,32})?\])/;
const MARKER_EXACT = /^\[REDACTED(?::[a-z-]{1,32})?\]$/;
const MIN_FRAGMENT = 8;

const AWS_KEY = /(?<![A-Za-z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Za-z0-9])/g;
const JWT = /(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g;
const GITHUB_TOKEN = /(?<![A-Za-z0-9_])(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})/g;
const SLACK_TOKEN = /(?<![A-Za-z0-9])xox[abposr]-[A-Za-z0-9-]{10,}/g;
const URL_CREDENTIALS = /(?<![A-Za-z0-9+.-])([A-Za-z][A-Za-z0-9+.-]{0,20}:\/\/)([^\s/@:]*:[^\s/@]+)@/g;
const AUTH_HEADER =
  /(authorization["']?[ \t]{0,3}[:=][ \t]{0,3}["']?)?(?<![A-Za-z0-9])(bearer|basic)([ \t]{1,5})([A-Za-z0-9+/=._~-]{8,})/gi;
const PASSWORD_PREFIX =
  /(?:password|passwd|passphrase|pwd)[A-Za-z0-9_-]{0,32}(?:\\*["'])?[ \t]{0,5}(?::=|=>|=|:)[ \t]{0,5}/gi;
const KEYED_TOKEN =
  /((?:api[_-]?key|secret|token|key|credentials?)[A-Za-z0-9_-]{0,32}(?:\\*["'])?[ \t]{0,5}(?::=|=>|=|:)[ \t]{0,5}(?:\\*["'])?)((?:[A-Za-z0-9+/_-]|\\\/|\\u[0-9A-Fa-f]{4}){20,}(?:=|\\u003[dD]){0,2})/gi;
const PRIVATE_KEY_BEGIN = /-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY(?: BLOCK)?-----/y;
const PRIVATE_KEY_END = /-----END [A-Z0-9 ]{0,40}PRIVATE KEY(?: BLOCK)?-----/y;

function isMarker(value: string): boolean {
  return MARKER_EXACT.test(value);
}

function tag(type: string): string {
  return `[REDACTED:${type}]`;
}

function toBase64Url(value: string): string {
  return value.replace(/\+/g, "-").replace(/\//g, "_");
}

function encodedForms(secret: string): string[] {
  const forms: string[] = [secret];
  const json = JSON.stringify(secret).slice(1, -1);
  forms.push(json, json.replace(/\//g, "\\/"));
  const percent = encodeURIComponent(secret);
  forms.push(
    percent,
    percent.replace(/%[0-9A-F]{2}/g, (m) => m.toLowerCase()),
    percent.replace(/%20/g, "+"),
  );
  const bytes = Buffer.from(secret, "utf8");
  const hex = bytes.toString("hex");
  if (hex.length >= MIN_FRAGMENT) forms.push(hex, hex.toUpperCase());
  const base64: string[] = [];
  for (let offset = 0; offset < 3; offset++) {
    const encoded = Buffer.concat([Buffer.alloc(offset), bytes]).toString("base64");
    if (offset === 0) base64.push(encoded, encoded.replace(/=+$/, ""));
    const core = encoded.slice(Math.ceil((8 * offset) / 6), Math.floor((8 * (offset + bytes.length)) / 6));
    if (core.length >= MIN_FRAGMENT) base64.push(core);
  }
  for (const form of base64) forms.push(form, toBase64Url(form));
  return forms;
}

function secretVariants(secrets: readonly string[] | undefined): string[] {
  const variants = new Set<string>();
  for (const secret of secrets ?? []) {
    if (typeof secret !== "string" || secret.length === 0) continue;
    for (const form of encodedForms(secret)) {
      if (form.length > 0) variants.add(form);
    }
  }
  return [...variants].sort((a, b) => b.length - a.length);
}

function redactKnown(text: string, variants: readonly string[]): { text: string; redactions: number } {
  if (variants.length === 0) return { text, redactions: 0 };
  let parts = text.split(MARKER_SPLIT).map((value, index) => ({ value, locked: index % 2 === 1 }));
  let redactions = 0;
  for (const variant of variants) {
    const next: { value: string; locked: boolean }[] = [];
    for (const part of parts) {
      if (part.locked || part.value.length < variant.length) {
        next.push(part);
        continue;
      }
      const pieces = part.value.split(variant);
      redactions += pieces.length - 1;
      pieces.forEach((piece, index) => {
        if (index > 0) next.push({ value: MARKER, locked: true });
        if (piece.length > 0) next.push({ value: piece, locked: false });
      });
    }
    parts = next;
  }
  return { text: parts.map((part) => part.value).join(""), redactions };
}

function matchSticky(re: RegExp, text: string, at: number): number {
  re.lastIndex = at;
  return re.test(text) ? re.lastIndex : -1;
}

function redactPrivateKeys(text: string): { text: string; redactions: number } {
  let out = "";
  let cursor = 0;
  let search = 0;
  let redactions = 0;
  while (search < text.length) {
    const begin = text.indexOf("-----BEGIN ", search);
    if (begin === -1) break;
    if (matchSticky(PRIVATE_KEY_BEGIN, text, begin) === -1) {
      search = begin + 1;
      continue;
    }
    let stop = text.length;
    let probe = text.indexOf("-----END ", begin);
    while (probe !== -1) {
      const end = matchSticky(PRIVATE_KEY_END, text, probe);
      if (end !== -1) {
        stop = end;
        break;
      }
      probe = text.indexOf("-----END ", probe + 1);
    }
    const block = text.slice(begin, stop);
    const newlines = block.split("\n").length - 1;
    out += text.slice(cursor, begin) + tag("private-key") + "\n".repeat(newlines);
    redactions++;
    cursor = stop;
    search = stop;
  }
  return { text: out + text.slice(cursor), redactions };
}

function hasLetterAndDigit(value: string): boolean {
  return /[A-Za-z]/.test(value) && /[0-9]/.test(value);
}

type Redaction = { text: string; redactions: number };
type Rule =
  | { re: RegExp; apply: (match: string, groups: string[]) => string }
  | { scan: (text: string) => Redaction };

function backslashRun(text: string, at: number): number {
  let end = at;
  while (text.charCodeAt(end) === 92) end++;
  return end - at;
}

type ValueSpan = { lead: string; bodyStart: number; bodyEnd: number; trail: string; end: number };

function scanQuoted(text: string, start: number, run: number, quote: string, anyDouble: boolean): ValueSpan | null {
  const bodyStart = start + run + 1;
  const lead = text.slice(start, bodyStart);
  const newlineRun = run > 0 && run % 2 === 1 ? (run + 1) / 2 : -1;
  let at = bodyStart;
  while (at < text.length) {
    const char = text[at];
    if (char === "\r" || char === "\n") break;
    const count = char === "\\" ? backslashRun(text, at) : 0;
    const next = text[at + count];
    if (quote === "'" && next === '"' && (anyDouble || count === 0)) break;
    if (next === quote) {
      if (count < run) break;
      if ((count - run) % (2 * (run + 1)) === 0) {
        const bodyEnd = at + count - run;
        return { lead, bodyStart, bodyEnd, trail: text.slice(bodyEnd, at + count + 1), end: at + count + 1 };
      }
    } else if (count > 0 && newlineRun > 0 && (next === "n" || next === "r") && count % (run + 1) === newlineRun) {
      return { lead, bodyStart, bodyEnd: at + count - newlineRun, trail: "", end: at + count - newlineRun };
    } else if (count > 0 && (next === undefined || next === "\r" || next === "\n")) {
      break;
    }
    at += count + 1;
  }
  if (quote === "'" && !anyDouble) return null;
  return { lead, bodyStart, bodyEnd: at, trail: "", end: at };
}

function scanUnquoted(text: string, start: number): ValueSpan {
  let at = start;
  while (at < text.length) {
    const char = text[at];
    if (/[\s"'`,;]/.test(char)) break;
    if (char === "\\") {
      const count = backslashRun(text, at);
      const next = text[at + count];
      if (next === undefined || /[\s"'`]/.test(next)) break;
      if (count % 2 === 1 && /[nrt]/.test(next)) break;
      at += count + 1;
      continue;
    }
    at++;
  }
  return { lead: "", bodyStart: start, bodyEnd: at, trail: "", end: at };
}

function scanValue(text: string, start: number): ValueSpan {
  const run = backslashRun(text, start);
  const next = text[start + run];
  if (next === '"' && (run === 0 || run % 2 === 1)) return scanQuoted(text, start, run, '"', true) as ValueSpan;
  if (next === "'" && run === 0) {
    return scanQuoted(text, start, 0, "'", false) ?? (scanQuoted(text, start, 0, "'", true) as ValueSpan);
  }
  return scanUnquoted(text, start);
}

function redactPasswords(text: string): Redaction {
  let out = "";
  let cursor = 0;
  let redactions = 0;
  PASSWORD_PREFIX.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = PASSWORD_PREFIX.exec(text)) !== null) {
    const valueStart = match.index + match[0].length;
    const span = scanValue(text, valueStart);
    const body = text.slice(span.bodyStart, span.bodyEnd);
    if (body.length > 0 && !isMarker(body)) {
      out += text.slice(cursor, valueStart) + span.lead + tag("password") + span.trail;
      cursor = span.end;
      redactions++;
    }
    PASSWORD_PREFIX.lastIndex = Math.max(span.end, valueStart + 1);
  }
  return { text: out + text.slice(cursor), redactions };
}

const RULES: readonly Rule[] = [
  { re: JWT, apply: () => tag("jwt") },
  { re: GITHUB_TOKEN, apply: () => tag("github-token") },
  { re: SLACK_TOKEN, apply: () => tag("slack-token") },
  { re: AWS_KEY, apply: () => tag("aws-key") },
  {
    re: URL_CREDENTIALS,
    apply: (match, [scheme, userinfo]) => {
      const password = userinfo.slice(userinfo.indexOf(":") + 1);
      if (isMarker(userinfo) || isMarker(password)) return match;
      return `${scheme}${tag("url-credentials")}@`;
    },
  },
  {
    re: AUTH_HEADER,
    apply: (match, [header, scheme, gap, value]) => {
      const qualifies = header !== undefined || /[0-9+/=_~]/.test(value);
      if (!qualifies) return match;
      return `${header ?? ""}${scheme}${gap}${tag("auth-header")}`;
    },
  },
  { scan: redactPasswords },
  {
    re: KEYED_TOKEN,
    apply: (match, [prefix, value]) => {
      if (!hasLetterAndDigit(value)) return match;
      return `${prefix}${tag("token")}`;
    },
  },
];

function redactPatterns(text: string): { text: string; redactions: number } {
  const keys = redactPrivateKeys(text);
  let current = keys.text;
  let redactions = keys.redactions;
  for (const rule of RULES) {
    if ("scan" in rule) {
      const scanned = rule.scan(current);
      current = scanned.text;
      redactions += scanned.redactions;
      continue;
    }
    rule.re.lastIndex = 0;
    current = current.replace(rule.re, (match: string, ...rest: unknown[]) => {
      const groups = rest.filter((_, index) => index < rest.length - 2) as string[];
      const replaced = rule.apply(match, groups);
      if (replaced !== match) redactions++;
      return replaced;
    });
  }
  return { text: current, redactions };
}

export function redactSecrets(
  text: string,
  knownSecrets?: readonly string[],
): { text: string; redactions: number } {
  if (text.length === 0) return { text, redactions: 0 };
  const known = redactKnown(text, secretVariants(knownSecrets));
  const patterns = redactPatterns(known.text);
  return { text: patterns.text, redactions: known.redactions + patterns.redactions };
}

export function containsSecret(text: string, secrets: readonly string[]): boolean {
  if (text.length === 0) return false;
  return secretVariants(secrets).some((variant) => text.includes(variant));
}
