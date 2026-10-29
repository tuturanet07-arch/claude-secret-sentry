# Claude Secret Sentry

A small, dependency-free Claude Code hook that blocks a proposed file write or edit when it resembles a common API key, access token, password assignment, or private key. It runs locally and does not send file contents anywhere.

This is a lightweight guardrail, not a secrets scanner or a guarantee that every credential will be caught. It scans only proposed content from `Write`, `Edit`, and `MultiEdit` calls; it does not scan Bash commands, existing files, prompts, or tool output. Review the patterns before relying on it in a sensitive environment.

## Install

1. Copy `.claude/hooks/secret_sentry.py` and `.claude/settings.json` into your project, preserving their paths.
2. Make the hook executable on macOS/Linux:

   ```sh
   chmod +x .claude/hooks/secret_sentry.py
   ```

3. Restart Claude Code or use `/hooks` to confirm the hook is loaded.

The project settings add a `PreToolUse` hook for file-writing tools. Existing settings can be merged with this `hooks` section. Claude Code still applies its normal permission flow to calls the hook does not block.

## What it catches

- PEM private-key headers
- AWS access key IDs (`AKIA…`)
- GitHub tokens (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, `github_pat_`)
- Slack tokens (`xox…`)
- Anthropic and OpenAI key-like strings
- Long values assigned to common names such as `API_KEY`, `access_token`, `client_secret`, or `password`

The checks are pattern-based. They can miss unfamiliar formats and can flag legitimate test values. The denial message names the category only and never prints the matched text.

## Quick manual check

Send a JSON hook event to the script and inspect its JSON response. A benign value returns no output; a matching value returns a `PreToolUse` deny decision.

```sh
printf '%s' '{"tool_name":"Write","tool_input":{"file_path":"config.py","content":"API_KEY=sk-ant-exampleNotARealSecretValue123456"}}' | .claude/hooks/secret_sentry.py
```

## License

MIT. See [LICENSE](LICENSE).
