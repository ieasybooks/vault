// Runs src/main.js as the runner does, in its own process, against a local
// server standing in for both GitHub's token endpoint and the vault.

import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

import { logLines, masksIn, parseEnvFile } from "./helpers.js";

const MAIN = fileURLToPath(new URL("../src/main.js", import.meta.url));
const ID_TOKEN = "header.payload.signature";
const PEM = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgabcdefghijklmnop\n-----END PRIVATE KEY-----";

// Answers token requests itself and vault requests from the queue.
async function standIn(vaultAnswers) {
  const requests = [];
  const server = createServer(async (request, response) => {
    let body = "";
    for await (const chunk of request) body += chunk;
    requests.push({ method: request.method, url: request.url, headers: request.headers, body });
    let answer;
    if (request.url.startsWith("/token")) {
      answer = request.headers.authorization === "Bearer request-token" ? { status: 200, body: { value: ID_TOKEN } } : { status: 403, body: {} };
    } else {
      answer = vaultAnswers.shift() ?? { status: 500, body: { error: "nothing queued" } };
    }
    response.writeHead(answer.status, { "content-type": "application/json", ...answer.headers });
    response.end(typeof answer.body === "string" ? answer.body : JSON.stringify(answer.body));
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const url = `http://127.0.0.1:${server.address().port}`;
  return { url, requests, close: () => new Promise((resolve) => server.close(resolve)) };
}

async function runMain(inputs, vaultAnswers, envOverrides = {}) {
  const stand = await standIn(vaultAnswers);
  const dir = await mkdtemp(join(tmpdir(), "vault-main-test-"));
  const githubEnv = join(dir, "github_env");
  const runnerTemp = join(dir, "runner_temp");
  await writeFile(githubEnv, "");
  await mkdir(runnerTemp);
  const env = {
    PATH: process.env.PATH,
    GITHUB_ENV: githubEnv,
    RUNNER_TEMP: runnerTemp,
    ACTIONS_ID_TOKEN_REQUEST_URL: `${stand.url}/token?api-version=2.0`,
    ACTIONS_ID_TOKEN_REQUEST_TOKEN: "request-token",
    INPUT_URL: stand.url,
    ...Object.fromEntries(Object.entries(inputs).map(([input, value]) => [`INPUT_${input.toUpperCase()}`, value])),
    ...envOverrides,
  };
  const started = Date.now();
  const child = spawn(process.execPath, [MAIN], { cwd: dir, env });
  let stdout = "";
  let stderr = "";
  child.stdout.on("data", (chunk) => (stdout += chunk));
  child.stderr.on("data", (chunk) => (stderr += chunk));
  const code = await new Promise((resolve) => child.on("close", resolve));
  await stand.close();
  const envText = await readFile(githubEnv, "utf8").catch(() => "");
  return { code, stdout, stderr, seconds: (Date.now() - started) / 1000, requests: stand.requests, variables: parseEnvFile(envText) };
}

test("serves secrets end to end", async () => {
  const values = { JSON_KEY: JSON.stringify({ key_id: "ABCDEFGHIJ", key: PEM }), PASSWORD: "p%40ss-word-0A", KEYSTORE: Buffer.from("keystore bytes\n").toString("base64") };
  const r = await runMain(
    { secrets: "JSON_KEY\nPASSWORD=STORE_PASSWORD", files: "JSON_KEY.json", "base64-files": "KEYSTORE.p12" },
    [{ status: 200, body: { secrets: values } }],
  );
  assert.equal(r.code, 0, r.stdout + r.stderr);
  assert.equal(r.stderr, "");

  const [token, vault] = r.requests;
  assert.equal(token.method, "GET");
  assert.match(token.url, /^\/token\?api-version=2\.0&audience=http%3A%2F%2F127\.0\.0\.1%3A\d+$/);
  assert.equal(vault.method, "POST");
  assert.equal(vault.url, "/ci");
  assert.equal(vault.headers.authorization, `Bearer ${ID_TOKEN}`);
  assert.equal(vault.headers["content-type"], "application/json");
  assert.deepEqual(JSON.parse(vault.body), { secrets: ["JSON_KEY", "PASSWORD", "KEYSTORE"] });

  assert.equal(r.variables.JSON_KEY, values.JSON_KEY);
  assert.equal(r.variables.STORE_PASSWORD, values.PASSWORD);
  assert.equal(await readFile(r.variables.JSON_KEY_FILE, "utf8"), values.JSON_KEY);
  assert.equal(await readFile(r.variables.KEYSTORE_FILE, "utf8"), "keystore bytes\n");
  assert.ok(r.variables.KEYSTORE_FILE.endsWith("/KEYSTORE.p12"));

  const masks = masksIn(r.stdout);
  for (const part of [ID_TOKEN, values.JSON_KEY, values.PASSWORD, values.KEYSTORE, ...PEM.split("\n")]) {
    assert.ok(masks.includes(part), `masks ${part}`);
  }
  const log = logLines(r.stdout);
  assert.equal(log[0], "The vault served JSON_KEY, PASSWORD, KEYSTORE:");
  for (const line of log) {
    for (const value of [ID_TOKEN, ...Object.values(values), ...PEM.split("\n")]) assert.ok(!line.includes(value), line);
  }
});

test("waits out a 503 for real", async () => {
  const r = await runMain({ secrets: "A" }, [
    { status: 503, headers: { "retry-after": "1" }, body: { error: "can't check this token's signing key yet; retry" } },
    { status: 200, body: { secrets: { A: "a-value" } } },
  ]);
  assert.equal(r.code, 0, r.stdout);
  assert.ok(r.seconds >= 1);
  assert.equal(r.variables.A, "a-value");
});

test("a refusal fails the step with one error annotation", async () => {
  const r = await runMain({ secrets: "A, B" }, [
    { status: 403, body: { error: "refused", refused: { B: "no rule matches push on refs/heads/x by someone, running y" } } },
  ]);
  assert.equal(r.code, 1);
  const errors = r.stdout.split("\n").filter((line) => line.startsWith("::error::"));
  assert.deepEqual(errors, ["::error::The vault refused this job:%0A  B: no rule matches push on refs/heads/x by someone, running y"]);
  assert.deepEqual(r.variables, {});
});

test("no id-token permission", async () => {
  const r = await runMain({ secrets: "A" }, [], { ACTIONS_ID_TOKEN_REQUEST_URL: "", ACTIONS_ID_TOKEN_REQUEST_TOKEN: "" });
  assert.equal(r.code, 1);
  assert.match(r.stdout, /^::error::This job can't get an OIDC token for the vault\. Give it `permissions: id-token: write`/m);
  assert.deepEqual(r.requests, []);
});

test("an unexpected error is reported without the values", async () => {
  // GITHUB_ENV is a directory, so appending to it fails after the values came.
  const dir = await mkdtemp(join(tmpdir(), "vault-main-test-"));
  const r = await runMain({ secrets: "A" }, [{ status: 200, body: { secrets: { A: "never-in-a-message" } } }], { GITHUB_ENV: dir });
  assert.equal(r.code, 1);
  assert.match(r.stdout, /^::error::Unexpected error: EISDIR/m);
  for (const line of logLines(r.stdout)) assert.ok(!line.includes("never-in-a-message"));
  assert.ok(!r.stdout.split("\n").some((line) => line.startsWith("::error::") && line.includes("never-in-a-message")));
});
