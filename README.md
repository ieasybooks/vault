# vault

A GitHub Action that fetches secrets from the ieasybooks vault at `vault.ieasybooks.com` into a job. The job proves who it is with its GitHub OIDC token. The vault hands over only the secrets whose rules match the job's repository, workflow, ref, event, actor and environment. The secrets and their rules live in `cloudflare/vault-secrets.tf` in [ieasybooks/infrastructure](https://github.com/ieasybooks/infrastructure), a private repository. On a Mac, `mise run vault:run` there does the same for a command.

## Usage

```yaml
jobs:
  release:
    runs-on: macos-latest
    permissions:
      contents: read
      id-token: write # lets the job prove who it is to the vault
    steps:
      - uses: ieasybooks/vault@<commit SHA> # v1
        with:
          secrets: |
            APPLE_DISTRIBUTION_CERTIFICATE_PASSWORD
            MOFIED_ANDROID_KEYSTORE_PASSWORD=KEYSTORE_PASSWORD
          files: APPLE_API_KEY.json
          base64-files: |
            APPLE_DISTRIBUTION_CERTIFICATE.p12
            MOFIED_ANDROID_KEYSTORE.p12=KEYSTORE_FILE
      - run: bundle exec fastlane release
```

| Input | Each entry | Puts |
|---|---|---|
| `secrets` | `NAME` or `NAME=VAR` | The value in `$NAME`, or `$VAR`. |
| `files` | `NAME` or `NAME.ext`, either with `=VAR` | The value in a file named `NAME.ext`, with its path in `$NAME_FILE`, or `$VAR`. |
| `base64-files` | Like `files` | The decoded bytes of a value stored as base64, such as a `.p12` or a keystore, in a file. |

Put entries one per line or separate them with commas; lines starting with `#` are comments. A secret can be in more than one input. Files go in a new directory under `$RUNNER_TEMP` that only the runner's user can read, and GitHub empties it when the job ends. Give a file the extension its tool expects: macOS's `security import`, which fastlane uses, can't read a `.p12` without one.

The vault serves every secret a step asks for, or none. If it refuses one, the step fails without setting anything, and the error says why for each refused secret.

### Checking that the vault refuses a secret

`expect-refused` lists secrets the vault must keep from the job, such as another workflow's deploy token, to check its rules from the job itself:

```yaml
      - uses: ieasybooks/vault@<commit SHA> # v1
        with:
          expect-refused: MOFIED_WEB_DEPLOY_TOKEN
```

- Each name is asked for in its own request, before any secret is fetched.
- Each must be refused because none of its rules matches the job, so the step proves that the rules keep the secret from it.
- Any other answer fails the step, because it proves nothing: the secret isn't in the vault, has no value yet, or isn't shared with this event; the token or the vault had a problem; or the vault served it. A value served by mistake is masked and dropped, never written or printed.
- It can be the only input, or come with the others.

## What it does

1. It asks GitHub for the job's OIDC token, with `https://vault.ieasybooks.com` as its audience, and masks the token.
2. It sends the token and the secrets' names to the vault's `POST /ci`.
   - 502 and 503 answers are retried after the time their `Retry-After` gives, for up to two minutes.
   - Network failures are retried three times.
   - A value set in the last few seconds takes a moment to reach the vault, which says it has no value until then. That answer is retried for up to 30 seconds.
3. It masks every value before printing anything:
   - a one-line value as a whole;
   - a multi-line value line by line;
   - in a JSON value, every string and every line of one, such as a private key's lines.

   Lines and strings shorter than 8 characters aren't masked, so a JSON key's braces don't hide every brace in the logs.
4. It writes the files, adds the variables to `$GITHUB_ENV`, and lists where each secret went.

## Security

- **Pin the action to a commit SHA**, as above, in workflows that get release secrets. A tag can be moved, and this code runs with every secret the job asks for.
- Every later step in the job, including other actions, can read the variables and the files. Fetch secrets in the job that needs them, as late as possible, and keep third-party actions out of that job where you can.
- The vault serves only GitHub-hosted runners, not self-hosted ones such as Blacksmith's, and only in ieasybooks repositories.
- Pull requests from forks get no OIDC token. Other runs that outsiders can start, such as pull requests, comments and issues, only get secrets the vault shares with them (`pull_requests = true`).
- Don't print secrets: masking is only a safety net. GitHub can't mask a value that a step changes into a form it doesn't know, such as part of a line.

## Development

`node --test test/*.test.js` runs the unit tests, then runs `src/main.js` against a local stand-in for GitHub and the vault. It needs Node 24, the runtime GitHub uses for this action, and nothing else: the action has no dependencies.

The Test workflow also runs the action against the real vault on pushes to `main`, on pull requests from branches here, and when started by hand. It fetches `TEST_SECRET`, a random value the vault shares with that workflow in this repository only, and then:

1. checks the value against the repository variable `TEST_SECRET_SHA256`;
2. checks every file it wrote;
3. checks that asking for a secret that isn't in the vault fails;
4. checks `expect-refused`: that the vault refuses this workflow `APPLE_API_KEY` because no rule matches, except on pull requests, where it refuses it for another reason; and that expecting a refusal of `TEST_SECRET`, which it does get, or of a secret that isn't in the vault, fails;
5. reads the jobs' logs to check that the value shows only as `***`.

To replace `TEST_SECRET`, from a checkout of ieasybooks/infrastructure:

```sh
file=$(mktemp)
openssl rand -base64 96 > "$file" # two lines, to test multi-line values
mise run vault:set TEST_SECRET < "$file"
gh variable set TEST_SECRET_SHA256 -R ieasybooks/vault --body "$(printf %s "$(cat "$file")" | shasum -a 256 | cut -d' ' -f1)"
rm "$file"
```

## Releases

Tag the release `vX.Y.Z`, then move `vX` to the same commit. Workflows that get release secrets pin the release's commit SHA, with the tag in a comment.
