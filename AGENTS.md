## Agent skills

### Issue tracker

Issues and PRDs for this repo live in GitHub Issues. See `.agents/issue-tracker.md`.

### GitHub comments

When writing multi-line GitHub issue or PR comments, pass real Markdown
newlines, not escaped `\n` text. Prefer a heredoc assigned to a shell variable,
then pass that variable to `gh`, for example:

```sh
body=$(cat <<'EOF'
已完成。对应提交：<commit-sha>。

完成内容：...

验证：...
EOF
)
gh issue close <number> --comment "$body"
```

### Triage labels

This repo uses the default five-label triage vocabulary. See `.agents/triage-labels.md`.

### Domain docs

This repo uses a single-context domain documentation layout. See `.agents/domain.md`.
