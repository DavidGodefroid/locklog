# locklog

Your AI reads the logs, not the people in them.

locklog lets an AI agent (Claude Code, Codex, Cursor, Gemini CLI) find when
something broke in your logs, over MCP, without reading them in clear. A
console held by a human, in its own account and container, reads the logs;
the agent gets masked, bounded answers. The personal data and secrets
locklog detects are masked before anything reaches the model.

**Status:** in development, no release yet. Nothing here is ready to use.

Loki 3 users: see [docs/loki.md](docs/loki.md) on the default `detected_level` field, which makes
level questions cheap without a `level` label.

## License

Apache License 2.0: see [LICENSE](LICENSE) and [NOTICE](NOTICE).
