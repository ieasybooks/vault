import { ActionError, escapeData, run } from "./vault.js";

try {
  await run();
} catch (error) {
  // Unexpected errors come from Node itself, for example writing a file, and
  // carry paths at most, never a value.
  const message = error instanceof ActionError ? error.message : `Unexpected error: ${error?.message ?? error}`;
  process.stdout.write(`::error::${escapeData(message)}\n`);
  process.exitCode = 1;
}
