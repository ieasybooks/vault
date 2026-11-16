// Shared by the tests: reading GITHUB_ENV and workflow commands the way the
// runner does.

// actions/runner's SetEnvFileCommand: NAME=value, or NAME<<DELIMITER, the
// value's lines, then DELIMITER on its own line.
export function parseEnvFile(text) {
  const variables = {};
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line === "") continue;
    const heredoc = line.indexOf("<<");
    const equals = line.indexOf("=");
    if (heredoc !== -1 && (equals === -1 || heredoc < equals)) {
      const name = line.slice(0, heredoc);
      const delimiter = line.slice(heredoc + 2);
      const value = [];
      for (i++; i < lines.length && lines[i] !== delimiter; i++) value.push(lines[i]);
      if (i === lines.length) throw new Error(`${name} never ends`);
      variables[name] = value.join("\n");
    } else {
      variables[line.slice(0, equals)] = line.slice(equals + 1);
    }
  }
  return variables;
}

// actions/runner's ActionCommand.UnescapeData.
export function unescapeData(text) {
  return text.replace(/%0D/g, "\r").replace(/%0A/g, "\n").replace(/%25/g, "%");
}

export function masksIn(stdout) {
  return stdout
    .split("\n")
    .filter((line) => line.startsWith("::add-mask::"))
    .map((line) => unescapeData(line.slice("::add-mask::".length)));
}

// The output with workflow commands removed: what shows in the log.
export function logLines(stdout) {
  return stdout.split("\n").filter((line) => line !== "" && !line.startsWith("::"));
}
