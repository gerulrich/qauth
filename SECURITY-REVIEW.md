# Security Review

## Findings

| # | Severity | File | Lines | Vulnerability | Confidence |
|---|----------|------|-------|---------------|------------|
| 1 | 🟡 MEDIUM | `src/main/resources/application-prod.properties` | 5 | Production Argon2id uses 8 MiB of memory, down from the previous 19 MiB setting. This reduces the cost of offline password guessing if the password database is exposed, particularly for weak passwords. Restore at least the previous memory cost or calibrate a stronger production setting. | 8/10 |
