import assert from "node:assert/strict";
import { mkdir, mkdtemp, readdir, readFile, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, test } from "node:test";

import { ActionError, envFileEntries, escapeData, maskedParts, parseExpectRefused, parseInputs, run, vaultUrl } from "../src/vault.js";
import { logLines, masksIn, parseEnvFile, unescapeData } from "./helpers.js";

const TOKEN_URL = "https://token.example/_apis/idtoken?api-version=2.0";
const ID_TOKEN = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJyZXBvIn0.c2lnbmF0dXJl";
const PEM = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgabcdefghijklmnop\nqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ\n-----END PRIVATE KEY-----\n";
const JSON_KEY = JSON.stringify(
  { type: "service_account", project_id: "faqieh", private_key: PEM, client_email: "release@faqieh.iam.gserviceaccount.com" },
  null,
  2,
);
const BINARY = Buffer.from([0, 1, 2, 250, 251, 252, 253, 254, 255, 10, 13, 37]);

const reply = (status, body, headers = {}) =>
  new Response(typeof body === "string" ? body : JSON.stringify(body), { status, headers });
const served = (secrets) => reply(200, { secrets });
const tokenReply = () => reply(200, { count: 1, value: ID_TOKEN });

// Runs the action against stand-ins for GitHub's token endpoint and the vault,
// which answer from queues, on a clock that only sleeps advance.
async function act(inputs, { token = [tokenReply()], vault = [], env: extraEnv = {} } = {}) {
  const dir = await mkdtemp(join(tmpdir(), "vault-action-test-"));
  const githubEnv = join(dir, "github_env");
  const runnerTemp = join(dir, "runner_temp");
  await writeFile(githubEnv, "EARLIER=kept\n");
  await mkdir(runnerTemp);
  const env = {
    GITHUB_ENV: githubEnv,
    RUNNER_TEMP: runnerTemp,
    ACTIONS_ID_TOKEN_REQUEST_URL: TOKEN_URL,
    ACTIONS_ID_TOKEN_REQUEST_TOKEN: "request-token",
    ...Object.fromEntries(Object.entries(inputs).map(([input, value]) => [`INPUT_${input.toUpperCase()}`, value])),
    ...extraEnv,
  };

  const queues = { token: [...token], vault: [...vault] };
  const calls = [];
  const fetch = async (url, init = {}) => {
    const kind = String(url).startsWith("https://token.example/") ? "token" : "vault";
    calls.push({ kind, url: String(url), init });
    const next = queues[kind].shift();
    if (next === undefined) throw new Error(`no ${kind} answer queued`);
    if (next instanceof Error) throw next;
    return next;
  };
  let time = 0;
  const sleeps = [];
  const sleep = async (ms) => {
    sleeps.push(ms);
    time += ms;
  };
  let stdout = "";

  let error;
  try {
    await run({ env, fetch, sleep, now: () => time, stdout: { write: (text) => (stdout += text) } });
  } catch (caught) {
    error = caught;
  }
  const envText = await readFile(githubEnv, "utf8").catch(() => "");
  return {
    error,
    stdout,
    calls,
    sleeps,
    runnerTemp,
    envText,
    variables: parseEnvFile(envText),
    left: queues,
    vaultCalls: calls.filter((call) => call.kind === "vault"),
  };
}

function assertActionError(result, pattern) {
  assert.ok(result.error instanceof ActionError, `expected an ActionError, got ${result.error?.stack ?? result.error}`);
  assert.match(result.error.message, pattern);
}

describe("parseInputs", () => {
  const parse = (inputs) =>
    parseInputs(Object.fromEntries(Object.entries(inputs).map(([key, value]) => [`INPUT_${key.toUpperCase()}`, value])));

  test("secrets: NAME and NAME=VAR, by line or comma, with comments, blanks and spaces", () => {
    const deliveries = parse({ secrets: "# a comment, with commas\nAPPLE_API_KEY\n\n  B = OTHER_VAR , C\r\nD=d_lower\n" });
    assert.deepEqual(deliveries, [
      { name: "APPLE_API_KEY", variable: "APPLE_API_KEY" },
      { name: "B", variable: "OTHER_VAR" },
      { name: "C", variable: "C" },
      { name: "D", variable: "d_lower" },
    ]);
  });

  test("files: NAME_FILE by default, extensions, =VAR", () => {
    assert.deepEqual(parse({ files: "A\nB.json\nC.tar.gz=C_PATH\nD=D_PATH" }), [
      { name: "A", variable: "A_FILE", file: "A", decode: false },
      { name: "B", variable: "B_FILE", file: "B.json", decode: false },
      { name: "C", variable: "C_PATH", file: "C.tar.gz", decode: false },
      { name: "D", variable: "D_PATH", file: "D", decode: false },
    ]);
  });

  test("base64-files decode", () => {
    assert.deepEqual(parse({ "base64-files": "CERT.p12" }), [{ name: "CERT", variable: "CERT_FILE", file: "CERT.p12", decode: true }]);
  });

  test("one secret can go to several places", () => {
    const deliveries = parse({ secrets: "A, A=A2", files: "A.txt", "base64-files": "A.bin=A_BIN" });
    assert.deepEqual(
      deliveries.map((d) => [d.name, d.variable, d.file]),
      [
        ["A", "A", undefined],
        ["A", "A2", undefined],
        ["A", "A_FILE", "A.txt"],
        ["A", "A_BIN", "A.bin"],
      ],
    );
  });

  for (const [inputs, pattern] of [
    [{}, /List the secrets/],
    [{ secrets: "\n # only a comment\n" }, /List the secrets/],
    [{ secrets: "apple_api_key" }, /secrets: "apple_api_key" isn't NAME or NAME=VAR/],
    [{ secrets: "1A" }, /isn't NAME/],
    [{ secrets: "A.json" }, /secrets: "A.json" isn't NAME or NAME=VAR/],
    [{ secrets: "A=1VAR" }, /isn't NAME/],
    [{ secrets: "A=B=C" }, /isn't NAME/],
    [{ secrets: "A B" }, /isn't NAME/],
    [{ files: "A=" }, /files: "A=" isn't NAME, NAME.ext/],
    [{ files: "A..json" }, /isn't NAME, NAME.ext/],
    [{ files: "A/../B" }, /isn't NAME, NAME.ext/],
    [{ "base64-files": "A.p12=" }, /base64-files: "A.p12=" isn't/],
    [{ secrets: "A, A" }, /A is set twice/],
    [{ secrets: "A=X, B=X" }, /X is set twice/],
    [{ secrets: "A_FILE", files: "A" }, /A_FILE is set twice/],
    [{ files: "A=X_FILE", "base64-files": "A=Y_FILE" }, /Two files would be named A/],
    [{ secrets: "A=GITHUB_TOKEN" }, /GITHUB_TOKEN is the runner's own variable/],
    [{ secrets: "A=github_path" }, /runner's own variable/],
    [{ secrets: "A=RUNNER_TEMP" }, /runner's own variable/],
    [{ secrets: "A=ACTIONS_ID_TOKEN_REQUEST_TOKEN" }, /runner's own variable/],
    [{ secrets: "A=PATH" }, /runner's own variable/],
    [{ secrets: "NODE_OPTIONS" }, /runner's own variable/],
    [{ files: "GITHUB" }, /GITHUB_FILE is the runner's own variable/],
  ]) {
    test(`refuses ${JSON.stringify(inputs)}`, () => {
      assert.throws(() => parse(inputs), (error) => error instanceof ActionError && pattern.test(error.message));
    });
  }
});

describe("parseExpectRefused", () => {
  const parse = (inputs) => {
    const env = Object.fromEntries(Object.entries(inputs).map(([key, value]) => [`INPUT_${key.toUpperCase()}`, value]));
    return parseExpectRefused(env, parseInputs(env));
  };

  test("names by line or comma, with comments", () => {
    assert.deepEqual(parse({ "expect-refused": "# what the web job must not get\nAPPLE_API_KEY, B\n\nC" }), ["APPLE_API_KEY", "B", "C"]);
  });

  test("works alone, without secrets to fetch", () => {
    assert.deepEqual(parse({ "expect-refused": "A" }), ["A"]);
  });

  for (const [inputs, pattern] of [
    [{ "expect-refused": "lower" }, /expect-refused: "lower" isn't a secret name/],
    [{ "expect-refused": "A=VAR" }, /expect-refused: "A=VAR" isn't a secret name/],
    [{ "expect-refused": "A.json" }, /isn't a secret name/],
    [{ "expect-refused": "A, B, A" }, /expect-refused lists A twice/],
    [{ secrets: "A", "expect-refused": "A" }, /A is both fetched and expected to be refused/],
    [{ files: "A.json", "expect-refused": "B, A" }, /A is both fetched and expected to be refused/],
    [{ "expect-refused": " # only a comment" }, /List the secrets to fetch .* or those the vault must refuse in expect-refused/],
  ]) {
    test(`refuses ${JSON.stringify(inputs)}`, () => {
      assert.throws(() => parse(inputs), (error) => error instanceof ActionError && pattern.test(error.message));
    });
  }
});

describe("vaultUrl", () => {
  test("defaults to the vault", () => {
    for (const input of [undefined, "", "  "]) assert.equal(vaultUrl(input), "https://vault.ieasybooks.com");
  });
  test("keeps only the origin", () => {
    assert.equal(vaultUrl("https://vault.ieasybooks.com/"), "https://vault.ieasybooks.com");
    assert.equal(vaultUrl(" https://VAULT.example.com:8443 "), "https://vault.example.com:8443");
    assert.equal(vaultUrl("http://127.0.0.1:4000"), "http://127.0.0.1:4000");
    assert.equal(vaultUrl("http://localhost:4000/"), "http://localhost:4000");
    assert.equal(vaultUrl("http://[::1]:4000"), "http://[::1]:4000");
  });
  for (const [input, pattern] of [
    ["vault.ieasybooks.com", /isn't a URL/],
    ["http://vault.ieasybooks.com", /must be on https/],
    ["ftp://vault.ieasybooks.com", /must be on https/],
    ["https://vault.ieasybooks.com/ci", /only the vault's origin/],
    ["https://vault.ieasybooks.com/?a=b", /only the vault's origin/],
    ["https://vault.ieasybooks.com/#x", /only the vault's origin/],
    ["https://user:pass@vault.ieasybooks.com", /only the vault's origin/],
  ]) {
    test(`refuses ${input}`, () => {
      assert.throws(() => vaultUrl(input), (error) => error instanceof ActionError && pattern.test(error.message));
    });
  }
});

describe("maskedParts", () => {
  test("a one-line value whole, however short, trimmed", () => {
    assert.deepEqual(maskedParts("abc"), ["abc"]);
    assert.deepEqual(maskedParts("  p@ss word  "), ["p@ss word"]);
  });

  test("a multi-line value line by line, skipping short lines", () => {
    assert.deepEqual(maskedParts("first-line-of-it\n}\r\n  second-line  \r\n\nshort"), ["first-line-of-it", "second-line"]);
  });

  test("a JSON key's strings, including each line of a private key", () => {
    const parts = maskedParts(JSON_KEY);
    for (const line of PEM.trim().split("\n")) assert.ok(parts.includes(line), `masks ${line}`);
    assert.ok(parts.includes("release@faqieh.iam.gserviceaccount.com"));
    assert.ok(parts.includes('"type": "service_account",'), "the JSON's own lines");
    assert.ok(!parts.includes("faqieh"), "not strings shorter than 8");
    assert.ok(!parts.includes("{") && !parts.includes("}"));
    assert.ok(!parts.some((part) => /[\r\n]/.test(part)), "only single lines");
  });

  test("compact JSON whole and its strings", () => {
    const value = JSON.stringify({ key_id: "RPQCS9379M", issuer_id: "6cad5e47-f5a2", key: PEM });
    const parts = maskedParts(value);
    assert.equal(parts[0], value);
    assert.ok(parts.includes("RPQCS9379M") && parts.includes("6cad5e47-f5a2"));
    assert.ok(parts.includes("qrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"));
  });

  test("strings nested in arrays", () => {
    assert.deepEqual(maskedParts('["first-secret",{"a":["second-secret",1,null]}]').slice(1), ["first-secret", "second-secret"]);
  });

  test("JSON that isn't an object or array is just a value", () => {
    assert.deepEqual(maskedParts("12345678901"), ["12345678901"]);
    assert.deepEqual(maskedParts('"quoted-secret"'), ['"quoted-secret"']);
  });
});

describe("escapeData", () => {
  test("escapes like GitHub's toolkit and round-trips through the runner", () => {
    assert.equal(escapeData("a%b\r\nc"), "a%25b%0D%0Ac");
    for (const text of ["%0A", "%25", "100%\n%0D\r", "plain"]) assert.equal(unescapeData(escapeData(text)), text);
  });
});

describe("envFileEntries", () => {
  test("round-trips values through the runner's parser", () => {
    const variables = { A: "one line", B: "two\nlines", C: "B<<EOF\nEOF\nghadelimiter_x", D: "=equals=" };
    const text = envFileEntries(variables);
    assert.deepEqual(parseEnvFile(text), variables);
    const delimiters = text.split("\n").filter((line) => /^[A-D]<<ghadelimiter_/.test(line)).map((line) => line.split("<<")[1]);
    assert.equal(new Set(delimiters).size, 4, "a new delimiter per variable");
  });
});

describe("expect-refused", () => {
  const NO_RULE = "no rule matches workflow_dispatch on refs/heads/main by AliOsm, running ieasybooks/mofied/.github/workflows/release-please.yml@refs/heads/main";
  const refusedFor = (name, why = NO_RULE) => reply(403, { error: "refused", refused: { [name]: why } });

  test("passes when the vault refuses the secret because no rule matches, without GITHUB_ENV", async () => {
    const r = await act({ "expect-refused": "WEB_TOKEN" }, { vault: [refusedFor("WEB_TOKEN")], env: { GITHUB_ENV: "", RUNNER_TEMP: "" } });
    assert.equal(r.error, undefined, r.error?.stack);
    assert.equal(r.vaultCalls.length, 1);
    assert.deepEqual(JSON.parse(r.vaultCalls[0].init.body), { secrets: ["WEB_TOKEN"] });
    assert.equal(r.vaultCalls[0].init.headers.authorization, `Bearer ${ID_TOKEN}`);
    assert.deepEqual(logLines(r.stdout), [`The vault refuses WEB_TOKEN to this job, as it should: ${NO_RULE}`]);
  });

  test("asks for each name in its own request", async () => {
    const r = await act({ "expect-refused": "A, B, C" }, { vault: [refusedFor("A"), refusedFor("B"), refusedFor("C")] });
    assert.equal(r.error, undefined, r.error?.stack);
    assert.deepEqual(
      r.vaultCalls.map((call) => JSON.parse(call.init.body)),
      [{ secrets: ["A"] }, { secrets: ["B"] }, { secrets: ["C"] }],
    );
  });

  test("checks the refusals before fetching, then fetches as usual", async () => {
    const r = await act({ secrets: "STORE_SECRET", "expect-refused": "WEB_TOKEN" }, { vault: [refusedFor("WEB_TOKEN"), served({ STORE_SECRET: "store-secret-value" })] });
    assert.equal(r.error, undefined, r.error?.stack);
    assert.deepEqual(
      r.vaultCalls.map((call) => JSON.parse(call.init.body)),
      [{ secrets: ["WEB_TOKEN"] }, { secrets: ["STORE_SECRET"] }],
    );
    assert.equal(r.variables.STORE_SECRET, "store-secret-value");
  });

  test("a secret served by mistake fails before anything is delivered, masked and never printed or written", async () => {
    const r = await act(
      { secrets: "STORE_SECRET", "expect-refused": "WEB_TOKEN" },
      { vault: [served({ WEB_TOKEN: "leaked-token-value" }), served({ STORE_SECRET: "store-secret-value" })] },
    );
    assertActionError(r, /^The vault served WEB_TOKEN, which this job must not get: no rule should match it\.$/);
    assert.ok(!r.error.message.includes("leaked-token-value"));
    assert.equal(r.vaultCalls.length, 1, "the secrets aren't fetched");
    assert.deepEqual(r.variables, { EARLIER: "kept" });
    assert.ok(masksIn(r.stdout).includes("leaked-token-value"));
    for (const line of logLines(r.stdout)) assert.ok(!line.includes("leaked-token-value"));
  });

  test("a served answer without the value still fails", async () => {
    const r = await act({ "expect-refused": "A" }, { vault: [reply(200, { secrets: {} })] });
    assertActionError(r, /^The vault served A, which this job must not get/);
  });

  test("other refusals prove nothing, and aren't waited out", async () => {
    for (const why of ["isn't in the vault", "has no value yet: mise run vault:set A", "isn't shared with pull_request runs"]) {
      const r = await act({ "expect-refused": "A" }, { vault: [refusedFor("A", why), refusedFor("A")] });
      assertActionError(r, new RegExp(`^The vault didn't refuse A because no rule matches, so this proves nothing: HTTP 403, ${why.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\.$`));
      assert.deepEqual(r.sleeps, []);
      assert.equal(r.vaultCalls.length, 1);
    }
  });

  test("a refusal of another secret doesn't count", async () => {
    const r = await act({ "expect-refused": "A" }, { vault: [refusedFor("B")] });
    assertActionError(r, /^The vault didn't refuse A because no rule matches, so this proves nothing: HTTP 403, refused\.$/);
  });

  test("token, server and other answers prove nothing", async () => {
    const cases = [
      [reply(401, { error: "token expired" }), /HTTP 401, token expired\.$/],
      [reply(403, { error: "only GitHub-hosted runners can use the vault" }), /HTTP 403, only GitHub-hosted runners can use the vault\.$/],
      [reply(500, "Internal Server Error"), /HTTP 500\.$/],
      [reply(404, { error: "not found" }), /HTTP 404, not found\.$/],
    ];
    for (const [answer, pattern] of cases) {
      const r = await act({ "expect-refused": "A" }, { vault: [answer] });
      assertActionError(r, pattern);
      assert.match(r.error.message, /^The vault didn't refuse A because no rule matches, so this proves nothing/);
    }
  });

  test("retries the vault's 502 and 503 and network failures, as a fetch does", async () => {
    const r = await act(
      { "expect-refused": "A" },
      { vault: [reply(503, { error: "keys loading" }, { "retry-after": "2" }), new TypeError("fetch failed"), refusedFor("A")] },
    );
    assert.equal(r.error, undefined, r.error?.stack);
    assert.deepEqual(r.sleeps, [2000, 5000]);
  });

  test("gives up on a vault it can't reach", async () => {
    const r = await act({ "expect-refused": "A" }, { vault: Array.from({ length: 4 }, () => new TypeError("fetch failed")) });
    assertActionError(r, /^Couldn't reach the vault at https:\/\/vault\.ieasybooks\.com: fetch failed\.$/);
  });

  test("stops at the first name that fails", async () => {
    const r = await act({ "expect-refused": "A, B" }, { vault: [refusedFor("A", "isn't in the vault"), refusedFor("B")] });
    assertActionError(r, /didn't refuse A/);
    assert.equal(r.vaultCalls.length, 1);
  });
});

describe("run", () => {
  test("puts secrets in the environment and in files", async () => {
    const values = { API_KEY: JSON_KEY, PASSWORD: "hunter2-but-longer", CERT: BINARY.toString("base64") };
    const r = await act(
      {
        secrets: "API_KEY\nPASSWORD=STORE_PASSWORD",
        files: "API_KEY.json",
        "base64-files": "CERT.p12=CERT_PATH",
      },
      { vault: [served(values)] },
    );
    assert.equal(r.error, undefined, r.error?.stack);

    const [token, vault] = r.calls;
    assert.equal(token.url, `${TOKEN_URL}&audience=${encodeURIComponent("https://vault.ieasybooks.com")}`);
    assert.equal(token.init.headers.authorization, "Bearer request-token");
    assert.equal(vault.url, "https://vault.ieasybooks.com/ci");
    assert.equal(vault.init.method, "POST");
    assert.equal(vault.init.headers.authorization, `Bearer ${ID_TOKEN}`);
    assert.equal(vault.init.headers["content-type"], "application/json");
    assert.deepEqual(JSON.parse(vault.init.body), { secrets: ["API_KEY", "PASSWORD", "CERT"] });

    assert.equal(r.variables.EARLIER, "kept");
    assert.equal(r.variables.API_KEY, JSON_KEY);
    assert.equal(r.variables.STORE_PASSWORD, values.PASSWORD);
    assert.ok(!("PASSWORD" in r.variables));

    const jsonPath = r.variables.API_KEY_FILE;
    const certPath = r.variables.CERT_PATH;
    assert.equal(dirname(jsonPath), dirname(certPath));
    assert.equal(dirname(dirname(jsonPath)), r.runnerTemp);
    assert.ok(jsonPath.endsWith("/API_KEY.json") && certPath.endsWith("/CERT.p12"));
    assert.equal(await readFile(jsonPath, "utf8"), JSON_KEY);
    assert.deepEqual(await readFile(certPath), BINARY);
    assert.equal((await stat(jsonPath)).mode & 0o777, 0o600);
    assert.equal((await stat(certPath)).mode & 0o777, 0o600);
    assert.equal((await stat(dirname(certPath))).mode & 0o777, 0o700);
    assert.deepEqual((await readdir(dirname(certPath))).sort(), ["API_KEY.json", "CERT.p12"]);
  });

  test("masks the token and every value before saying anything else", async () => {
    const values = { API_KEY: JSON_KEY, PASSWORD: "100%-secret", CERT: BINARY.toString("base64") };
    const r = await act({ secrets: "API_KEY, PASSWORD", "base64-files": "CERT" }, { vault: [served(values)] });
    assert.equal(r.error, undefined, r.error?.stack);

    const masks = masksIn(r.stdout);
    assert.ok(masks.includes(ID_TOKEN));
    assert.ok(masks.includes("100%-secret"), "escaped and unescaped intact");
    assert.ok(masks.includes(values.CERT));
    for (const line of PEM.trim().split("\n")) assert.ok(masks.includes(line));

    const lines = r.stdout.split("\n");
    const lastMask = lines.findLastIndex((line) => line.startsWith("::add-mask::"));
    const firstOther = lines.findIndex((line) => line !== "" && !line.startsWith("::add-mask::"));
    assert.ok(lastMask < firstOther, "masks come first");

    const log = logLines(r.stdout).join("\n");
    assert.equal(
      log,
      [
        "The vault served API_KEY, PASSWORD, CERT:",
        "  API_KEY in $API_KEY",
        "  PASSWORD in $PASSWORD",
        "  CERT in the file at $CERT_FILE, decoded from base64",
      ].join("\n"),
    );
  });

  test("decodes base64 wrapped over lines", async () => {
    const bytes = Buffer.alloc(200, 7);
    const wrapped = bytes.toString("base64").replace(/.{76}/g, "$&\n");
    const r = await act({ "base64-files": "KEYSTORE" }, { vault: [served({ KEYSTORE: wrapped })] });
    assert.equal(r.error, undefined, r.error?.stack);
    assert.deepEqual(await readFile(r.variables.KEYSTORE_FILE), bytes);
  });

  for (const value of ["not base64!", "abc", "YWJj\n=YWJj", "YW Jj?", "====", "-_-_"]) {
    test(`refuses to decode ${JSON.stringify(value)}, writing nothing`, async () => {
      const r = await act({ secrets: "OK", "base64-files": "BAD" }, { vault: [served({ OK: "fine-value", BAD: value })] });
      assertActionError(r, /^BAD isn't base64, so it can't go in base64-files/);
      assert.ok(!r.error.message.includes(value));
      assert.deepEqual(r.variables, { EARLIER: "kept" });
      assert.deepEqual(await readdir(r.runnerTemp), []);
    });
  }

  test("runs twice in one job without clashing", async () => {
    const r1 = await act({ files: "A" }, { vault: [served({ A: "first-value" })] });
    const again = await act({ files: "A" }, { vault: [served({ A: "second-value" })], env: { RUNNER_TEMP: r1.runnerTemp } });
    assert.equal(again.error, undefined, again.error?.stack);
    assert.notEqual(r1.variables.A_FILE, again.variables.A_FILE);
    assert.equal(await readFile(r1.variables.A_FILE, "utf8"), "first-value");
  });

  test("asks for each secret once, keeping the order", async () => {
    const r = await act({ secrets: "B, A=A2", files: "A.txt", "base64-files": "C" }, { vault: [served({ A: "aaaa", B: "bbbb", C: "Y2Nj" })] });
    assert.equal(r.error, undefined, r.error?.stack);
    assert.deepEqual(JSON.parse(r.vaultCalls[0].init.body).secrets, ["B", "A", "C"]);
  });

  test("goes to another vault, with that as the token's audience", async () => {
    const r = await act({ secrets: "A", url: "https://vault.example.com/" }, { vault: [served({ A: "aaaa" })] });
    assert.equal(r.error, undefined, r.error?.stack);
    assert.match(r.calls[0].url, /&audience=https%3A%2F%2Fvault\.example\.com$/);
    assert.equal(r.vaultCalls[0].url, "https://vault.example.com/ci");
  });

  describe("retries", () => {
    test("503 after its Retry-After", async () => {
      const r = await act({ secrets: "A" }, { vault: [reply(503, { error: "can't check this token's signing key yet; retry" }, { "retry-after": "2" }), served({ A: "aaaa" })] });
      assert.equal(r.error, undefined, r.error?.stack);
      assert.deepEqual(r.sleeps, [2000]);
      assert.equal(r.variables.A, "aaaa");
      assert.ok(logLines(r.stdout).includes("The vault asks to retry in 2s: can't check this token's signing key yet; retry."));
    });

    test("502, 5s without a usable Retry-After, at least 1s", async () => {
      const r = await act(
        { secrets: "A" },
        {
          vault: [
            reply(502, { error: "couldn't fetch signing keys" }),
            reply(503, "<html>", { "retry-after": "soon" }),
            reply(503, {}, { "retry-after": "0" }),
            reply(502, { error: 42 }, { "retry-after": "Wed, 21 Oct 2026 07:28:00 GMT" }),
            served({ A: "aaaa" }),
          ],
        },
      );
      assert.equal(r.error, undefined, r.error?.stack);
      assert.deepEqual(r.sleeps, [5000, 5000, 1000, 5000]);
      assert.ok(logLines(r.stdout).includes("The vault asks to retry in 5s: HTTP 503."));
    });

    test("gives up when the wait would pass two minutes", async () => {
      const r = await act({ secrets: "A" }, { vault: [reply(503, { error: "busy" }, { "retry-after": "50" }), reply(503, { error: "busy" }, { "retry-after": "50" }), reply(503, { error: "still busy" }, { "retry-after": "50" })] });
      assertActionError(r, /^The vault still can't answer after trying for 120s: still busy\.$/);
      assert.deepEqual(r.sleeps, [50000, 50000]);
    });

    test("doesn't wait for a Retry-After past two minutes", async () => {
      const r = await act({ secrets: "A" }, { vault: [reply(503, { error: "busy" }, { "retry-after": "300" })] });
      assertActionError(r, /still can't answer/);
      assert.deepEqual(r.sleeps, []);
    });

    test("network failures, three times", async () => {
      const failure = () => Object.assign(new TypeError("fetch failed"), { cause: new Error("getaddrinfo ENOTFOUND vault.ieasybooks.com") });
      const r = await act({ secrets: "A" }, { vault: [failure(), failure(), failure(), served({ A: "aaaa" })] });
      assert.equal(r.error, undefined, r.error?.stack);
      assert.deepEqual(r.sleeps, [5000, 5000, 5000]);
      assert.ok(logLines(r.stdout).includes("Couldn't reach the vault (getaddrinfo ENOTFOUND vault.ieasybooks.com); retrying in 5s."));

      const r2 = await act({ secrets: "A" }, { vault: [failure(), failure(), failure(), failure()] });
      assertActionError(r2, /^Couldn't reach the vault at https:\/\/vault\.ieasybooks\.com: getaddrinfo ENOTFOUND vault\.ieasybooks\.com\.$/);
    });

    test("a request that times out", async () => {
      const r = await act({ secrets: "A" }, { vault: [new DOMException("The operation was aborted due to timeout", "TimeoutError"), served({ A: "aaaa" })] });
      assert.equal(r.error, undefined, r.error?.stack);
      assert.ok(logLines(r.stdout).includes("Couldn't reach the vault (no answer within 30s); retrying in 5s."));
    });

    test("a value set seconds ago, for up to 30s", async () => {
      const settling = () => reply(403, { error: "refused", refused: { A: "has no value yet: mise run vault:set A", B: "has no value yet: mise run vault:set B" } });
      const r = await act({ secrets: "A, B" }, { vault: [settling(), settling(), served({ A: "aaaa", B: "bbbb" })] });
      assert.equal(r.error, undefined, r.error?.stack);
      assert.deepEqual(r.sleeps, [5000, 5000]);
      assert.ok(logLines(r.stdout).includes("The vault has no value yet for A, B. A value set seconds ago takes a moment to reach it; retrying in 5s."));

      const r2 = await act({ secrets: "A, B" }, { vault: Array.from({ length: 8 }, settling) });
      assertActionError(r2, /^The vault refused this job:\n  A: has no value yet: mise run vault:set A\n  B: has no value yet: mise run vault:set B$/);
      assert.deepEqual(r2.sleeps, [5000, 5000, 5000, 5000, 5000, 5000]);
      assert.equal(r2.left.vault.length, 1);
    });

    test("not a refusal for other reasons", async () => {
      const r = await act(
        { secrets: "A, B" },
        { vault: [reply(403, { error: "refused", refused: { A: "has no value yet: mise run vault:set A", B: "no rule matches push on refs/heads/main by someone, running x" } })] },
      );
      assertActionError(r, /^The vault refused this job:\n  A: has no value yet.*\n  B: no rule matches push on refs\/heads\/main/);
      assert.deepEqual(r.sleeps, []);
    });
  });

  describe("failures", () => {
    test("other answers, with the vault's reason", async () => {
      const cases = [
        [reply(401, { error: "token expired" }), /^The vault answered HTTP 401: token expired\.$/],
        [reply(403, { error: "only GitHub-hosted runners can use the vault" }), /^The vault answered HTTP 403: only GitHub-hosted runners can use the vault\.$/],
        [reply(403, { error: "refused", refused: {} }), /^The vault answered HTTP 403: refused\.$/],
        [reply(500, "Internal Server Error"), /^The vault answered HTTP 500\.$/],
        [reply(404, { error: { nested: true } }), /^The vault answered HTTP 404\.$/],
      ];
      for (const [answer, pattern] of cases) {
        const r = await act({ secrets: "A" }, { vault: [answer] });
        assertActionError(r, pattern);
        assert.deepEqual(r.sleeps, []);
        assert.deepEqual(r.variables, { EARLIER: "kept" });
      }
    });

    test("an answer without a secret it asked for", async () => {
      for (const body of [{ secrets: { A: "aaaa" } }, { secrets: { A: "aaaa", B: "" } }, { secrets: { A: "aaaa", B: 7 } }, { secrets: null }, {}]) {
        const r = await act({ secrets: "A, B" }, { vault: [reply(200, body)] });
        assertActionError(r, /^The vault's answer has no (A|B)\.$/);
        assert.deepEqual(r.variables, { EARLIER: "kept" });
      }
    });

    test("a 200 that isn't JSON never shows its body", async () => {
      const r = await act({ secrets: "A" }, { vault: [reply(200, '{"secrets":{"A":"leaky-value"')] });
      assertActionError(r, /^The vault's answer has no A\.$/);
      assert.ok(!r.stdout.includes("leaky-value"));
    });

    test("no OIDC token without id-token: write", async () => {
      for (const missing of ["ACTIONS_ID_TOKEN_REQUEST_URL", "ACTIONS_ID_TOKEN_REQUEST_TOKEN"]) {
        const r = await act({ secrets: "A" }, { env: { [missing]: "" } });
        assertActionError(r, /can't get an OIDC token for the vault\. Give it `permissions: id-token: write`/);
        assert.deepEqual(r.calls, []);
      }
    });

    test("GitHub's token endpoint: retries 5xx, 429 and network failures, not refusals", async () => {
      const ok = await act({ secrets: "A" }, { token: [reply(500, "oops"), reply(429, ""), new TypeError("fetch failed"), tokenReply()], vault: [served({ A: "aaaa" })] });
      assert.equal(ok.error, undefined, ok.error?.stack);
      assert.deepEqual(ok.sleeps, [5000, 5000, 5000]);

      const down = await act({ secrets: "A" }, { token: [reply(503, ""), reply(503, ""), reply(503, ""), reply(503, "")] });
      assertActionError(down, /^Couldn't get an OIDC token from GitHub: HTTP 503\.$/);
      assert.equal(down.vaultCalls.length, 0);

      const refused = await act({ secrets: "A" }, { token: [reply(403, "no")] });
      assertActionError(refused, /^GitHub refused the job an OIDC token \(HTTP 403\)\.$/);
      assert.deepEqual(refused.sleeps, []);

      const empty = await act({ secrets: "A" }, { token: [reply(200, { count: 0 })] });
      assertActionError(empty, /has no token/);
    });

    test("outside a runner", async () => {
      const noEnv = await act({ secrets: "A" }, { env: { GITHUB_ENV: "" } });
      assertActionError(noEnv, /GITHUB_ENV isn't set/);
      assert.deepEqual(noEnv.calls, []);

      const noTemp = await act({ files: "A" }, { env: { RUNNER_TEMP: "" } });
      assertActionError(noTemp, /RUNNER_TEMP isn't set/);
      assert.deepEqual(noTemp.calls, []);

      const envOnly = await act({ secrets: "A" }, { env: { RUNNER_TEMP: "" }, vault: [served({ A: "aaaa" })] });
      assert.equal(envOnly.error, undefined, envOnly.error?.stack);
    });

    test("bad inputs before any request", async () => {
      const r = await act({ secrets: "lower" });
      assertActionError(r, /isn't NAME/);
      assert.deepEqual(r.calls, []);
      const url = await act({ secrets: "A", url: "http://vault.ieasybooks.com" });
      assertActionError(url, /must be on https/);
      assert.deepEqual(url.calls, []);
    });
  });
});
