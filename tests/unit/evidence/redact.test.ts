import { describe, it, expect } from "vitest";
import { redactSecrets, containsSecret } from "../../../src/evidence/redact";

const AWS_ID = "AKIAIOSFODNN7EXAMPLE";
const AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
const GENERIC = "f3a9c1d27b8e4056a1d9e2c47b3f8a60e5d4c3b2";
const PASSWORD_LINE = 'password = "admin1234"';

describe("redactSecrets with known secrets", () => {
  it("replaces each known secret with [REDACTED] everywhere", () => {
    const input = `a ${AWS_SECRET} b ${GENERIC} c ${AWS_SECRET}`;
    const result = redactSecrets(input, [AWS_SECRET, GENERIC]);
    expect(result.text).toBe("a [REDACTED] b [REDACTED] c [REDACTED]");
    expect(result.text).not.toContain(AWS_SECRET);
    expect(result.text).not.toContain(GENERIC);
  });

  it("redacts the base64 form of a known secret", () => {
    const encoded = Buffer.from(AWS_SECRET).toString("base64");
    const result = redactSecrets(`token=${encoded} end`, [AWS_SECRET]);
    expect(result.text).not.toContain(encoded);
    expect(result.text).toContain("[REDACTED]");
    expect(result.text.endsWith(" end")).toBe(true);
  });

  it("redacts the URL-encoded form of a known secret", () => {
    const encoded = encodeURIComponent(AWS_SECRET);
    expect(encoded).not.toBe(AWS_SECRET);
    const result = redactSecrets(`https://x.test/?k=${encoded}&z=1`, [AWS_SECRET]);
    expect(result.text).not.toContain(encoded);
    expect(result.text).toBe("https://x.test/?k=[REDACTED]&z=1");
  });

  it("counts every replacement", () => {
    const result = redactSecrets(`${GENERIC} and ${GENERIC} and ${AWS_ID}`, [GENERIC, AWS_ID]);
    expect(result.redactions).toBe(3);
  });

  it("reports zero redactions when nothing matches", () => {
    const result = redactSecrets("nothing to see here", [GENERIC]);
    expect(result).toEqual({ text: "nothing to see here", redactions: 0 });
  });
});

describe("redactSecrets pattern backstop", () => {
  it("redacts the AWS access key id shape without a known list", () => {
    const result = redactSecrets(`id: ${AWS_ID} done`);
    expect(result.text).not.toContain(AWS_ID);
    expect(result.text).toContain("[REDACTED");
    expect(result.redactions).toBeGreaterThanOrEqual(1);
  });

  it("redacts a long hex token after a key-like name", () => {
    const result = redactSecrets(`api_key = ${GENERIC}`);
    expect(result.text).not.toContain(GENERIC);
    expect(result.text).toContain("api_key");
    expect(result.redactions).toBeGreaterThanOrEqual(1);
  });

  it("redacts password assignments", () => {
    const result = redactSecrets(`config:\n${PASSWORD_LINE}\nnext`);
    expect(result.text).not.toContain("admin1234");
    expect(result.text).toContain("password");
    expect(result.redactions).toBeGreaterThanOrEqual(1);
  });
});

describe("redactSecrets keeps context (TS-028)", () => {
  it("keeps file names, line numbers and surrounding text", () => {
    const input = `src/config/aws.ts:42: found key ${AWS_ID} in assignment`;
    const result = redactSecrets(input, [AWS_ID]);
    expect(result.text).toBe("src/config/aws.ts:42: found key [REDACTED] in assignment");
  });

  it("keeps multi-line structure and line count", () => {
    const input = `line1\nkey=${GENERIC}\nline3\n`;
    const result = redactSecrets(input, [GENERIC]);
    expect(result.text.split("\n")).toHaveLength(4);
    expect(result.text.startsWith("line1\n")).toBe(true);
    expect(result.text.endsWith("\nline3\n")).toBe(true);
  });
});

describe("redactSecrets robustness", () => {
  it("is idempotent", () => {
    const input = `${AWS_ID} ${PASSWORD_LINE} api_key = ${GENERIC} ${AWS_SECRET}`;
    const once = redactSecrets(input, [AWS_SECRET]);
    expect(once.text).not.toBe(input);
    const twice = redactSecrets(once.text, [AWS_SECRET]);
    expect(twice.text).toBe(once.text);
    expect(twice.redactions).toBe(0);
  });

  it("handles empty input", () => {
    expect(redactSecrets("")).toEqual({ text: "", redactions: 0 });
    expect(redactSecrets("", [GENERIC])).toEqual({ text: "", redactions: 0 });
  });

  it("does not redact ordinary words and short numbers", () => {
    const input = "The password policy was reviewed in 2024, version 1234, port 8080.";
    const result = redactSecrets(input);
    expect(result).toEqual({ text: input, redactions: 0 });
  });

  it("ignores empty strings in the known secrets list", () => {
    const result = redactSecrets("plain text", [""]);
    expect(result).toEqual({ text: "plain text", redactions: 0 });
  });

  it("processes 1 MB of input in under 500 ms", () => {
    const chunk = `ordinary line of text without secrets 12345\n${PASSWORD_LINE}\n`;
    const input = chunk.repeat(Math.ceil((1024 * 1024) / chunk.length));
    const start = performance.now();
    const result = redactSecrets(input, [AWS_SECRET]);
    const elapsed = performance.now() - start;
    expect(elapsed).toBeLessThan(500);
    expect(result.redactions).toBeGreaterThan(0);
    expect(result.text).not.toContain("admin1234");
  });
});

describe("containsSecret", () => {
  it("finds the raw form", () => {
    expect(containsSecret(`x ${GENERIC} y`, [GENERIC])).toBe(true);
  });

  it("finds the base64 form", () => {
    const encoded = Buffer.from(AWS_SECRET).toString("base64");
    expect(containsSecret(`v=${encoded}`, [AWS_SECRET])).toBe(true);
  });

  it("finds the URL-encoded form", () => {
    expect(containsSecret(`k=${encodeURIComponent(AWS_SECRET)}`, [AWS_SECRET])).toBe(true);
  });

  it("returns false for clean text", () => {
    expect(containsSecret("nothing here", [AWS_SECRET, GENERIC])).toBe(false);
  });

  it("returns false for an empty secrets list or empty secret", () => {
    expect(containsSecret(GENERIC, [])).toBe(false);
    expect(containsSecret("abc", [""])).toBe(false);
  });
});

describe("redactSecrets ReDoS protection", () => {
  const SIZE = 200 * 1024;
  const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  const repeatTo = (unit: string, size: number) => unit.repeat(Math.ceil(size / unit.length)).slice(0, size);
  const hostile: [string, string][] = [
    ["base64 alphabet without terminator", repeatTo(B64, SIZE)],
    ["base64 alphabet after token=", `token=${repeatTo(B64, SIZE)}`],
    ["password= followed by many characters", `password=${"a1!".repeat(Math.ceil(SIZE / 3))}`.slice(0, SIZE)],
    ["password= with an unterminated quote", `password="${"x".repeat(SIZE)}`],
    ["long run of =", "=".repeat(SIZE)],
    ["long run of -", "-".repeat(SIZE)],
    ["key followed by long run of =", `api_key${"=".repeat(SIZE)}`],
    ["bearer followed by long run", `Bearer ${"=".repeat(SIZE)}`],
    ["url scheme repeated", "a://".repeat(Math.ceil(SIZE / 4))],
    ["private key begin without end", `-----BEGIN RSA PRIVATE KEY-----\n${repeatTo(B64, SIZE)}`],
    ["many private key begins without end", "-----BEGIN PRIVATE KEY-----\n".repeat(Math.ceil(SIZE / 28))],
    ["many END markers without begin", "-----END PRIVATE KEY-----\n".repeat(Math.ceil(SIZE / 26))],
  ];

  for (const [name, input] of hostile) {
    it(`stays under 1000 ms on 200 kB: ${name}`, { timeout: 15000 }, () => {
      const start = performance.now();
      const result = redactSecrets(input, [AWS_SECRET]);
      const elapsed = performance.now() - start;
      expect(typeof result.text).toBe("string");
      expect(elapsed).toBeLessThan(1000);
    });
  }
});

describe("redactSecrets exact output", () => {
  it("redacts the base64 form of a known secret exactly", () => {
    const encoded = Buffer.from(AWS_SECRET).toString("base64");
    const result = redactSecrets(`token=${encoded} end`, [AWS_SECRET]);
    expect(result.text).toBe("token=[REDACTED] end");
  });

  it("redacts a quoted password assignment exactly and leaves no part of the value", () => {
    const result = redactSecrets('password = "admin1234"');
    expect(result.text).toBe('password = "[REDACTED:password]"');
    expect(result.text).not.toContain("admin");
    expect(result.text).not.toContain("1234");
    expect(result.redactions).toBe(1);
  });

  it("does not keep the last character of an unquoted password value", () => {
    const result = redactSecrets("password=hunter2xyz9 next");
    expect(result.text).toBe("password=[REDACTED:password] next");
    expect(result.text).not.toContain("9");
  });

  it("does not keep the last character of a quoted password value", () => {
    const result = redactSecrets("db_password: 'Zq81mxyz!' end");
    expect(result.text).not.toContain("Zq81");
    expect(result.text).not.toContain("xyz!");
    expect(result.text).not.toContain("!'");
    expect(result.text.endsWith(" end")).toBe(true);
  });

  it("leaves no part of a 40 character key after a pattern replacement", () => {
    const result = redactSecrets(`api_key = "${GENERIC}"`);
    expect(result.text).toBe('api_key = "[REDACTED:token]"');
    for (let i = 0; i + 6 <= GENERIC.length; i++) {
      expect(result.text).not.toContain(GENERIC.slice(i, i + 6));
    }
  });
});

describe("redactSecrets credential shapes", () => {
  it("redacts URL credentials and keeps the surrounding text", () => {
    const result = redactSecrets("clone https://user:s3cretpass@host/x now");
    expect(result.text).toBe("clone https://[REDACTED:url-credentials]@host/x now");
    expect(result.text).not.toContain("s3cretpass");
  });

  it("redacts a Bearer header and keeps the surrounding text", () => {
    const result = redactSecrets("Authorization: Bearer abc123DEF456ghi789 tail");
    expect(result.text).toBe("Authorization: Bearer [REDACTED:auth-header] tail");
    expect(result.text).not.toContain("abc123DEF456ghi789");
  });

  it("redacts a Basic header and keeps the surrounding text", () => {
    const value = Buffer.from("user:password123").toString("base64");
    const result = redactSecrets(`Authorization: Basic ${value} tail`);
    expect(result.text).toBe("Authorization: Basic [REDACTED:auth-header] tail");
    expect(result.text).not.toContain(value);
  });

  it("redacts a complete private key block and keeps the surrounding text", () => {
    const body = "MIIEowIBAAKCAQEAabc123\nxyz789LONGBODYLINE\nQ0ZGRkZG";
    const input = `before\n-----BEGIN RSA PRIVATE KEY-----\n${body}\n-----END RSA PRIVATE KEY-----\nafter`;
    const result = redactSecrets(input);
    expect(result.text.startsWith("before\n[REDACTED:private-key]")).toBe(true);
    expect(result.text.endsWith("\nafter")).toBe(true);
    expect(result.text).not.toContain("BEGIN");
    expect(result.text).not.toContain("END RSA");
    expect(result.text).not.toContain("MIIEow");
    expect(result.text).not.toContain("xyz789");
    expect(result.text).not.toContain("Q0ZGRkZG");
    expect(result.text.split("\n")).toHaveLength(input.split("\n").length);
  });

  it("redacts a known secret that is JSON-escaped inside a JSON string", () => {
    const secret = 'pa"ss\\wordX9/1';
    const input = JSON.stringify({ a: "x", msg: `val ${secret} end`, z: 1 });
    expect(input).not.toContain(secret);
    const result = redactSecrets(input, [secret]);
    expect(result.text).toBe('{"a":"x","msg":"val [REDACTED] end","z":1}');
    expect(() => JSON.parse(result.text)).not.toThrow();
  });

  it("redacts a password assignment inside a JSON string and leaves no value", () => {
    const input = JSON.stringify({ a: "x", msg: 'password = "admin1234"', z: 1 });
    const result = redactSecrets(input);
    expect(result.text).not.toContain("admin1234");
    expect(result.text).not.toContain("admin");
    expect(result.text.startsWith('{"a":"x","msg":"password')).toBe(true);
    expect(result.text.endsWith(',"z":1}')).toBe(true);
  });

  it("redacts a JSON property named password", () => {
    const result = redactSecrets(JSON.stringify({ a: "x", password: "admin1234", z: 1 }));
    expect(result.text).toBe('{"a":"x","password":"[REDACTED:password]","z":1}');
  });
});

describe("redactSecrets longest known secret first", () => {
  it("replaces the longer secret as a whole when a shorter one is its prefix", () => {
    const result = redactSecrets("x abcdef y", ["abc", "abcdef"]);
    expect(result.text).toBe("x [REDACTED] y");
    expect(result.redactions).toBe(1);
  });

  it("gives the same result regardless of list order", () => {
    expect(redactSecrets("x abcdef y", ["abcdef", "abc"]).text).toBe("x [REDACTED] y");
  });
});

describe("redactSecrets nested JSON encodings", () => {
  const nest = (value: unknown, depth: number): string => {
    let text = JSON.stringify(value);
    for (let i = 1; i < depth; i++) text = JSON.stringify(text);
    return text;
  };
  const unnest = (text: string, depth: number): unknown => {
    let current: unknown = text;
    for (let i = 0; i < depth; i++) {
      expect(typeof current).toBe("string");
      current = JSON.parse(current as string);
    }
    return current;
  };
  const fragments = (value: string): string[] => {
    const out: string[] = [];
    for (let i = 0; i + 4 <= value.length; i++) out.push(value.slice(i, i + 4));
    return out;
  };
  const PASSWORD_VALUE = 'p"a\\ss';
  const cases: [string, unknown, string][] = [
    ["msg with password assignment", { a: "x", msg: PASSWORD_LINE, z: 1 }, "admin1234"],
    ["password field with quotes and backslashes", { a: "x", password: PASSWORD_VALUE, z: 1 }, PASSWORD_VALUE],
  ];

  for (const depth of [2, 3, 4]) {
    for (const [name, value, secret] of cases) {
      it(`leaves no fragment and stays valid JSON at depth ${depth}: ${name}`, () => {
        const input = nest(value, depth);
        const result = redactSecrets(input);
        expect(result.redactions).toBeGreaterThanOrEqual(1);
        const probes = fragments(secret);
        expect(probes.length).toBeGreaterThan(0);
        let current: unknown = result.text;
        for (let level = 0; level < depth; level++) {
          expect(typeof current).toBe("string");
          for (const probe of probes) expect(current as string).not.toContain(probe);
          current = JSON.parse(current as string);
        }
        const finalObject = current as { a: string; z: number };
        expect(finalObject.a).toBe("x");
        expect(finalObject.z).toBe(1);
        expect(JSON.stringify(finalObject)).not.toContain(secret);
        for (const probe of probes) expect(JSON.stringify(finalObject)).not.toContain(probe);
        expect(unnest(result.text, depth)).toEqual(finalObject);
      });

      it(`is idempotent at depth ${depth}: ${name}`, () => {
        const once = redactSecrets(nest(value, depth));
        const twice = redactSecrets(once.text);
        expect(twice.text).toBe(once.text);
        expect(twice.redactions).toBe(0);
      });
    }
  }
});

describe("redactSecrets single-quoted values", () => {
  const SECRET = "Zq81mxyz!pw";
  const probes = ["Zq81", "q81m", "81mx", "1mxy", "mxyz", "xyz!", "yz!p", "z!pw"];

  it("redacts a closed single-quoted value in plain text", () => {
    const result = redactSecrets(`password = '${SECRET}' end`);
    for (const probe of probes) expect(result.text).not.toContain(probe);
    expect(result.text.endsWith(" end")).toBe(true);
  });

  it("redacts a closed single-quoted value inside a JSON string and keeps valid JSON", () => {
    const input = JSON.stringify({ a: "x", msg: `password = '${SECRET}' end`, z: 1 });
    const result = redactSecrets(input);
    for (const probe of probes) expect(result.text).not.toContain(probe);
    const parsed = JSON.parse(result.text) as { a: string; msg: string; z: number };
    expect(parsed.a).toBe("x");
    expect(parsed.z).toBe(1);
    expect(parsed.msg.endsWith(" end")).toBe(true);
  });

  it("leaves no fragment of an unclosed single-quoted value inside a JSON string", () => {
    const input = JSON.stringify({ a: "x", msg: `password = '${SECRET}`, z: 1 });
    const result = redactSecrets(input);
    for (const probe of probes) expect(result.text).not.toContain(probe);
    const parsed = JSON.parse(result.text) as { a: string; msg: string; z: number };
    expect(parsed.a).toBe("x");
    expect(parsed.z).toBe(1);
  });

  it("leaves no fragment of an unclosed single-quoted value followed by text inside a JSON string", () => {
    const input = JSON.stringify({ a: "x", msg: `password = '${SECRET} trailing`, z: 1 });
    const result = redactSecrets(input);
    for (const probe of probes) expect(result.text).not.toContain(probe);
    expect(() => JSON.parse(result.text)).not.toThrow();
  });

  it("is idempotent on single-quoted output", () => {
    for (const msg of [`password = '${SECRET}' end`, `password = '${SECRET}`]) {
      const once = redactSecrets(JSON.stringify({ msg }));
      const twice = redactSecrets(once.text);
      expect(twice.text).toBe(once.text);
    }
  });
});

describe("redactSecrets escaped slash and unicode escapes in keyed tokens", () => {
  const SLASHED = "f3a9\\/c1d27b8e4056a1d9e2c47b3f8a60";
  const UNICODE = "f3a9\\u002fc1d27b8e4056a1d9e2c47b3f8a60";
  const PARTS = ["f3a9", "c1d2", "7b8e", "4056", "a1d9", "e2c4", "7b3f", "8a60"];

  it("fully redacts a value containing an escaped slash", () => {
    const input = `{"api_key": "${SLASHED}", "z": 1}`;
    const result = redactSecrets(input);
    expect(result.text).toBe('{"api_key": "[REDACTED:token]", "z": 1}');
    for (const part of PARTS) expect(result.text).not.toContain(part);
  });

  it("fully redacts a value containing a unicode escape", () => {
    const input = `{"api_key": "${UNICODE}", "z": 1}`;
    const result = redactSecrets(input);
    expect(result.text).toBe('{"api_key": "[REDACTED:token]", "z": 1}');
    for (const part of PARTS) expect(result.text).not.toContain(part);
  });

  it("fully redacts a token with a unicode-escaped padding sign", () => {
    const input = '{"token": "abcDEF123abcDEF123abcDEF123\\u003d\\u003d"}';
    const result = redactSecrets(input);
    expect(result.text).toBe('{"token": "[REDACTED:token]"}');
  });

  it.fails("known gap: escaped-slash value inside a JSON string (double-escaped backslash)", () => {
    const input = JSON.stringify({ msg: `{"api_key": "${SLASHED}"}` });
    const result = redactSecrets(input);
    for (const part of PARTS) expect(result.text).not.toContain(part);
    expect(() => JSON.parse(result.text)).not.toThrow();
  });
});

describe("redactSecrets known gaps", () => {
  it.fails("known gap: unquoted value containing a double quote", () => {
    const result = redactSecrets("password=a\"dm next");
    expect(result.text).not.toContain("dm");
    expect(result.text).toBe("password=[REDACTED:password] next");
  });
});
