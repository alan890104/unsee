<div align="center">

# unsee

**Credential protection for LLM coding agents.**

Stop secrets from leaking into AI context windows — without changing your workflow.

[![Crates.io](https://img.shields.io/crates/v/unsee?style=flat-square)](https://crates.io/crates/unsee)
[![License](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange?style=flat-square&logo=rust)](https://www.rust-lang.org)
[![macOS](https://img.shields.io/badge/macOS-supported-brightgreen?style=flat-square&logo=apple)](https://github.com/alan890104/unsee)
[![Linux](https://img.shields.io/badge/Linux-supported-brightgreen?style=flat-square&logo=linux&logoColor=white)](https://github.com/alan890104/unsee)

<br>

<p>
<code>.env</code> stays untouched — developers and apps see real values.<br>
LLM agents see only placeholders like <code>unsee:a1b2c3d4e5f6h7i8</code>.
</p>

</div>

---

<div align="center">
<h2>Use Cases</h2>
<table>
<tr>
<td width="60" align="center">🔐</td>
<td><strong>Prevent secret leaks in AI-generated PRs</strong><br>Agents write code with real keys they read from <code>.env</code> — unsee makes that impossible.</td>
</tr>
<tr>
<td align="center">🛡️</td>
<td><strong>Block prompt injection credential exfiltration</strong><br>A malicious markdown file can instruct the agent to dump secrets it has seen. With unsee, there's nothing to dump.</td>
</tr>
<tr>
<td align="center">🤖</td>
<td><strong>Protect credentials across all LLM agents</strong><br>Works with Claude Code, Codex, Gemini CLI, and any future agent — no per-tool config needed.</td>
</tr>
<tr>
<td align="center">☁️</td>
<td><strong>Guard cloud credentials and SSH keys</strong><br>Kernel-level sandbox blocks agent access to <code>~/.aws</code>, <code>~/.ssh</code>, <code>~/.kube</code>, while <code>ssh</code>/<code>git</code>/<code>aws</code> CLI still work normally.</td>
</tr>
<tr>
<td align="center">📝</td>
<td><strong>Keep shell history private</strong><br>Prevent agents from reading <code>~/.zsh_history</code> or <code>~/.bash_history</code> where past commands may contain tokens.</td>
</tr>
<tr>
<td align="center">✏️</td>
<td><strong>Auto-restore secrets in agent-written files</strong><br>If the agent writes a placeholder to <code>.env</code>, the write guard intercepts and restores the real value instantly.</td>
</tr>
</table>
</div>

---

## Installation

### Homebrew (recommended)

```bash
brew install alan890104/tap/unsee
```

### From source

```bash
cargo install --git https://github.com/alan890104/unsee unsee-cli
```

### Setup

```bash
# Install shell wrappers for claude, codex, gemini (bash/zsh/fish)
unsee install

# That's it. Use your agent normally — protection is automatic.
claude "fix the auth bug"
```

---

## How it works

| Layer | What it does |
|-------|-------------|
| **Shell wrapper** | `unsee install` wraps `claude`/`codex`/`gemini` — no config needed |
| **Env injection** | Real values injected as env vars so the app runs normally |
| **Output redaction** | PTY intercepts stdout/stderr, replaces real values with placeholders |
| **Process cleanup** | Double-exec scrubs secrets from `/proc/*/cmdline` |
| **Kernel sandbox** | macOS Seatbelt / Linux Landlock+seccomp blocks reads to `~/.ssh`, `~/.aws`, etc. |
| **Write guard** | DYLD/LD\_PRELOAD intercepts `write()` to `.env*` files, restores real values if agent writes placeholders |

## Quick start

```bash
# Install shell wrappers (bash/zsh/fish)
unsee install

# Now use your agent normally -- protection is automatic
claude "fix the auth bug"
codex "add retry logic"
gemini "refactor the db layer"

# Or protect a single command
unsee protect -- claude "why is the API returning 401?"
```

## What's protected

- **Environment files**: `.env`, `.env.local`, `.env.production`, plus editor backups (`.env~`, `#.env#`)
- **Cloud credentials**: `~/.aws`, `~/.azure`, `~/.config/gcloud`, `~/.kube`, `~/.docker`
- **SSH/GPG keys**: `~/.ssh`, `~/.gnupg`
- **Shell history**: `~/.bash_history`, `~/.zsh_history`, `~/.psql_history`, `~/.node_repl_history`, ...
- **AI tool state**: `~/.claude`, `~/.gemini`, `~/.codex`, `~/.codeium`, `~/.config/github-copilot`
- **Package manager tokens**: `~/.npmrc`, `~/.pypirc`, `~/.cargo/credentials.toml`, `~/.composer/auth.json`
- **IDE extension secrets**: VS Code / Cursor / Windsurf / Positron globalStorage directories
- **Git/network credentials**: `~/.git-credentials`, `~/.netrc`

Per-process exceptions: `ssh` can still read `~/.ssh`, `git` can read `~/.git-credentials`, `aws` can read `~/.aws` — but the LLM agent cannot.

## Configuration

```bash
# Initialize ignore list (variables that don't need protection)
unsee init

# Skip non-secret variables
unsee ignore DEBUG
unsee ignore PORT

# Check what's being protected
unsee status
```

`.unsee.ignore` lists variables to pass through unredacted (e.g. `DEBUG`, `PORT`, `NODE_ENV`).

`~/.unsee/credentials.conf` customizes protected credential paths:
```
# Add custom credential store
+~/.my-tokens
# SSH is handled by agent forwarding, no need to block
-~/.ssh
```

## Building

```bash
cargo build --release    # binary at target/release/unsee
```

## Testing

```bash
cargo test --workspace          # macOS native
make test-linux-arm64           # Linux arm64 (Docker)
make test-linux-amd64           # Linux amd64 (Docker)
```

## License

MIT
