// Fetches secrets from the ieasybooks vault into a GitHub Actions job: the job
// proves who it is with its GitHub OIDC token, the vault checks that against
// each secret's rules, and the values go into the environment of the job's
// later steps or into files. See README.md.
//
// No dependencies, so it runs straight from the repository on the runner's Node.

import { randomUUID } from "node:crypto";
import { appendFile, mkdtemp, writeFile } from "node:fs/promises";
import { join } from "node:path";

export const DEFAULT_URL = "https://vault.ieasybooks.com";

const REQUEST_TIMEOUT_MS = 30_000;
// The vault's 502 and 503 answers carry Retry-After; they're retried for up
// to two minutes, like mise run vault:run does on our Macs.
const RETRY_FOR_MS = 120_000;
const DEFAULT_RETRY_AFTER_S = 5;
// A value set seconds ago can take about 15 seconds to reach the vault, which
// until then says the secret has no value yet.
const NO_VALUE_RETRY_FOR_MS = 30_000;
const NO_VALUE_RETRY_EVERY_MS = 5_000;
const NETWORK_RETRIES = 3;
const NETWORK_RETRY_EVERY_MS = 5_000;
// Parts of a value (its lines, and the strings in a JSON value) shorter than
// this aren't masked: lines like "}" would hide every brace in the logs.
const MIN_MASKED_PART = 8;

const SECRET_ENTRY = /^([A-Z][A-Z0-9_]*)(?:=([A-Za-z_][A-Za-z0-9_]*))?$/;
const FILE_ENTRY = /^([A-Z][A-Z0-9_]*)((?:\.[A-Za-z0-9_-]+)*)(?:=([A-Za-z_][A-Za-z0-9_]*))?$/;
// Variables the runner or later steps rely on.
const RESERVED_VARIABLE = /^(GITHUB_|RUNNER_|ACTIONS_)|^(NODE_OPTIONS|PATH)$/i;

// A failure to report as is: its message never contains a secret's value.
export class ActionError extends Error {}

export async function run({
  env = process.env,
  fetch = globalThis.fetch,
  sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
  now = Date.now,
  stdout = process.stdout,
} = {}) {
  const deliveries = parseInputs(env);
  const url = vaultUrl(env.INPUT_URL);
  const githubEnv = env.GITHUB_ENV;
  if (!githubEnv) throw new ActionError("GITHUB_ENV isn't set: run this action in a GitHub Actions job.");
  const runnerTemp = env.RUNNER_TEMP;
  if (!runnerTemp && deliveries.some((d) => d.file)) {
    throw new ActionError("RUNNER_TEMP isn't set: files need a GitHub Actions runner.");
  }

  const io = { fetch, sleep, now, log: (line) => stdout.write(`${line}\n`) };
  const mask = (part) => stdout.write(`::add-mask::${escapeData(part)}\n`);

  const token = await idToken(env, url, io);
  mask(token);
  const names = [...new Set(deliveries.map((d) => d.name))];
  const values = await askVault(url, token, names, io);
  // Before anything else can print them.
  for (const name of names) for (const part of maskedParts(values[name])) mask(part);

  const contents = deliveries.map((d) => (d.decode ? decodeBase64(d.name, values[d.name]) : values[d.name]));
  const variables = {};
  let dir;
  for (const [i, d] of deliveries.entries()) {
    if (!d.file) {
      variables[d.variable] = contents[i];
      continue;
    }
    dir ??= await mkdtemp(join(runnerTemp, "vault-"));
    const path = join(dir, d.file);
    await writeFile(path, contents[i], { mode: 0o600, flag: "wx" });
    variables[d.variable] = path;
  }
  await appendFile(githubEnv, envFileEntries(variables));

  io.log(`The vault served ${names.join(", ")}:`);
  for (const d of deliveries) io.log(`  ${describe(d)}`);
}

// The secrets, files and base64-files inputs, one entry per line or comma:
//   secrets:            NAME or NAME=VAR, VAR holding the value
//   files/base64-files: NAME, NAME.ext or either with =VAR, VAR (NAME_FILE by
//                       default) holding the path of a file named NAME.ext
export function parseInputs(env) {
  const deliveries = [];
  for (const [input, file, decode] of [
    ["secrets", false, false],
    ["files", true, false],
    ["base64-files", true, true],
  ]) {
    for (const entry of entries(env[`INPUT_${input.toUpperCase()}`])) {
      deliveries.push(file ? fileEntry(input, entry, decode) : secretEntry(entry));
    }
  }
  if (deliveries.length === 0) {
    throw new ActionError("List the secrets to fetch in secrets, files or base64-files.");
  }

  const variables = new Set();
  const files = new Set();
  for (const d of deliveries) {
    if (RESERVED_VARIABLE.test(d.variable)) {
      throw new ActionError(`${d.variable} is the runner's own variable; pick another name with ${d.name}=VAR.`);
    }
    if (variables.has(d.variable)) {
      throw new ActionError(`${d.variable} is set twice; give one of them another name with NAME=VAR.`);
    }
    variables.add(d.variable);
    if (d.file) {
      if (files.has(d.file)) throw new ActionError(`Two files would be named ${d.file}; give one an extension, as in ${d.file}.txt.`);
      files.add(d.file);
    }
  }
  return deliveries;
}

// Lines starting with # are comments.
function entries(text) {
  return (text ?? "")
    .split(/\r?\n/)
    .filter((line) => !line.trim().startsWith("#"))
    .flatMap((line) => line.split(","))
    .map((entry) => entry.trim().replace(/\s*=\s*/, "="))
    .filter((entry) => entry !== "");
}

function secretEntry(entry) {
  const match = SECRET_ENTRY.exec(entry);
  if (!match) throw new ActionError(`secrets: "${entry}" isn't NAME or NAME=VAR, with NAME like APPLE_API_KEY.`);
  const [, name, variable = name] = match;
  return { name, variable };
}

function fileEntry(input, entry, decode) {
  const match = FILE_ENTRY.exec(entry);
  if (!match) {
    throw new ActionError(`${input}: "${entry}" isn't NAME, NAME.ext or either with =VAR, with NAME like APPLE_API_KEY.`);
  }
  const [, name, extension, variable = `${name}_FILE`] = match;
  return { name, variable, file: name + extension, decode };
}

function describe(d) {
  if (!d.file) return `${d.name} in $${d.variable}`;
  return `${d.name} in the file at $${d.variable}${d.decode ? ", decoded from base64" : ""}`;
}

// The vault's own address is also the audience of the token sent to it, so a
// token for one address is useless at another.
export function vaultUrl(input) {
  const text = input?.trim() || DEFAULT_URL;
  let url;
  try {
    url = new URL(text);
  } catch {
    throw new ActionError(`url: "${text}" isn't a URL.`);
  }
  const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
  if (url.protocol !== "https:" && !(url.protocol === "http:" && loopback)) {
    throw new ActionError(`url: the vault must be on https: ${text}.`);
  }
  if (url.pathname !== "/" || url.search || url.hash || url.username || url.password) {
    throw new ActionError(`url: give only the vault's origin, like ${DEFAULT_URL}: ${text}.`);
  }
  return url.origin;
}

// GitHub's OIDC token for the job, with the vault as its audience. The job
// gets ACTIONS_ID_TOKEN_REQUEST_* only with the id-token: write permission.
async function idToken(env, audience, { fetch, sleep, log }) {
  const requestUrl = env.ACTIONS_ID_TOKEN_REQUEST_URL;
  const requestToken = env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
  if (!requestUrl || !requestToken) {
    throw new ActionError(
      "This job can't get an OIDC token for the vault. Give it `permissions: id-token: write`; " +
        "runs for pull requests from forks never get one.",
    );
  }
  const url = new URL(requestUrl);
  url.searchParams.set("audience", audience);

  for (let attempt = 0; ; attempt++) {
    let problem;
    try {
      const response = await fetch(url, {
        headers: { authorization: `Bearer ${requestToken}`, accept: "application/json" },
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
      if (response.ok) {
        const token = parseJson(await response.text())?.value;
        if (typeof token === "string" && token !== "") return token;
        throw new ActionError("GitHub's answer to the OIDC token request has no token.");
      }
      if (response.status < 500 && response.status !== 429) {
        throw new ActionError(`GitHub refused the job an OIDC token (HTTP ${response.status}).`);
      }
      problem = `HTTP ${response.status}`;
    } catch (error) {
      if (error instanceof ActionError) throw error;
      problem = reason(error);
    }
    if (attempt === NETWORK_RETRIES) throw new ActionError(`Couldn't get an OIDC token from GitHub: ${problem}.`);
    log(`Couldn't get an OIDC token from GitHub (${problem}); retrying in ${NETWORK_RETRY_EVERY_MS / 1000}s.`);
    await sleep(NETWORK_RETRY_EVERY_MS);
  }
}

// POST /ci answers with every secret asked for, or refuses them all.
async function askVault(url, token, names, { fetch, sleep, now, log }) {
  const started = now();
  let networkFailures = 0;
  for (;;) {
    let response;
    let body;
    try {
      response = await fetch(`${url}/ci`, {
        method: "POST",
        headers: { authorization: `Bearer ${token}`, "content-type": "application/json", accept: "application/json" },
        body: JSON.stringify({ secrets: names }),
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
      // Never in an error message: a 200's body holds the values.
      body = parseJson(await response.text());
    } catch (error) {
      networkFailures++;
      const problem = reason(error);
      if (networkFailures > NETWORK_RETRIES || now() - started + NETWORK_RETRY_EVERY_MS > RETRY_FOR_MS) {
        throw new ActionError(`Couldn't reach the vault at ${url}: ${problem}.`);
      }
      log(`Couldn't reach the vault (${problem}); retrying in ${NETWORK_RETRY_EVERY_MS / 1000}s.`);
      await sleep(NETWORK_RETRY_EVERY_MS);
      continue;
    }
    if (response.status === 200) return servedValues(body, names);
    const detail = typeof body?.error === "string" ? body.error : null;
    const error = detail ?? `HTTP ${response.status}`;

    if (response.status === 502 || response.status === 503) {
      const wait = retryAfterSeconds(response.headers.get("retry-after"));
      if (now() - started + wait * 1000 > RETRY_FOR_MS) {
        throw new ActionError(`The vault still can't answer after trying for ${RETRY_FOR_MS / 1000}s: ${error}.`);
      }
      log(`The vault asks to retry in ${wait}s: ${error}.`);
      await sleep(wait * 1000);
      continue;
    }

    if (response.status === 403 && isObject(body?.refused) && Object.keys(body.refused).length > 0) {
      const refused = Object.entries(body.refused).map(([name, why]) => [name, String(why)]);
      const settling = refused.every(([, why]) => why.startsWith("has no value yet"));
      if (settling && now() - started + NO_VALUE_RETRY_EVERY_MS <= NO_VALUE_RETRY_FOR_MS) {
        log(
          `The vault has no value yet for ${refused.map(([name]) => name).join(", ")}. ` +
            `A value set seconds ago takes a moment to reach it; retrying in ${NO_VALUE_RETRY_EVERY_MS / 1000}s.`,
        );
        await sleep(NO_VALUE_RETRY_EVERY_MS);
        continue;
      }
      throw new ActionError(["The vault refused this job:", ...refused.map(([name, why]) => `  ${name}: ${why}`)].join("\n"));
    }

    throw new ActionError(`The vault answered HTTP ${response.status}${detail ? `: ${detail}` : ""}.`);
  }
}

function servedValues(body, names) {
  const served = isObject(body?.secrets) ? body.secrets : {};
  const values = {};
  for (const name of names) {
    const value = served[name];
    if (typeof value !== "string" || value === "") throw new ActionError(`The vault's answer has no ${name}.`);
    values[name] = value;
  }
  return values;
}

function retryAfterSeconds(header) {
  return /^\d+$/.test(header ?? "") ? Math.max(1, Number(header)) : DEFAULT_RETRY_AFTER_S;
}

// What to register with ::add-mask::. A one-line value is masked whole. The
// runner masks log output line by line, so a multi-line value is masked line
// by line, as are the strings in a JSON value, such as the lines of a private
// key, which appear unescaped only once a tool has parsed the JSON.
export function maskedParts(value) {
  const parts = new Set();
  const lines = linesOf(value);
  if (lines.length === 1) parts.add(lines[0]);
  else for (const line of lines) if (line.length >= MIN_MASKED_PART) parts.add(line);

  const parsed = parseJson(value);
  if (parsed !== null && typeof parsed === "object") {
    for (const text of stringsIn(parsed)) {
      for (const line of linesOf(text)) if (line.length >= MIN_MASKED_PART) parts.add(line);
    }
  }
  return [...parts];
}

function linesOf(text) {
  return text
    .split(/\r\n|\r|\n/)
    .map((line) => line.trim())
    .filter((line) => line !== "");
}

function* stringsIn(value) {
  if (typeof value === "string") yield value;
  else if (value !== null && typeof value === "object") for (const item of Object.values(value)) yield* stringsIn(item);
}

// Strict, so a value that isn't base64 fails instead of decoding to garbage.
// Line breaks are allowed, as base64 tools wrap long output.
function decodeBase64(name, value) {
  const compact = value.replace(/\s+/g, "");
  if (compact.length % 4 !== 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(compact)) {
    throw new ActionError(`${name} isn't base64, so it can't go in base64-files; use files to write it as is.`);
  }
  return Buffer.from(compact, "base64");
}

// GITHUB_ENV's multi-line syntax, with a random delimiter as GitHub's toolkit
// does, so a value can't end its entry early.
export function envFileEntries(variables) {
  let text = "";
  for (const [variable, value] of Object.entries(variables)) {
    const delimiter = `ghadelimiter_${randomUUID()}`;
    if (value.includes(delimiter)) throw new ActionError(`${variable}'s value contains its delimiter; run the job again.`);
    text += `${variable}<<${delimiter}\n${value}\n${delimiter}\n`;
  }
  return text;
}

// How GitHub's toolkit escapes a workflow command's data.
export function escapeData(text) {
  return text.replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");
}

function parseJson(text) {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

function isObject(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function reason(error) {
  if (error?.name === "TimeoutError") return `no answer within ${REQUEST_TIMEOUT_MS / 1000}s`;
  return error?.cause?.message ?? error?.message ?? String(error);
}
