# Goal
Expand CICD-Guard's built-in rules to cover more platforms (Azure, GitLab, Jenkins, GitHub) and common security issues.


# Requirements

## 1. Rule Categories
Add new rules with platform awareness:

### 🔑 Secrets
- Detect AWS access keys (`AKIA[0-9A-Z]{16}`)
- Detect Azure connection strings (`DefaultEndpointsProtocol=https;AccountName=...;AccountKey=...`)
- Detect GitHub tokens (`ghp_[A-Za-z0-9]{36}`)
- Detect generic high-entropy secrets (≥40 chars, random-looking)

### ⚙️ Misconfigurations
- **GitHub Actions**
  - Warn if `uses: actions/...@master` (unpinned action)
  - Warn if `permissions: write-all`
- **GitLab CI**
  - Warn if default branch hardcoded as `master` instead of `main`
  - Detect jobs without `only/except` → insecure triggering
- **Azure Pipelines**
  - Detect `pool: vmImage: 'windows-latest'` (use pinned versions)
  - Detect inline secrets in YAML (`password: ...`, `connectionString: ...`)
- **Jenkins**
  - Warn on `withCredentials` using plaintext
  - Detect hardcoded passwords in Groovy DSL

## 2. Implementation
- Add new rules in `rules/builtin.go`.
- Each rule = struct with:
  - `ID`
  - `Description`
  - `Regex` or `CustomFunc`
  - `AppliesTo` (list: [github, gitlab, azure, jenkins, all])
  - `Severity` (High, Medium, Low)

- Extend scanner:
  - Auto-detect platform by file path (`.github/workflows/` → GitHub, `.gitlab-ci.yml` → GitLab, etc.)
  - Apply relevant rules per platform.
  - Always run global rules (e.g., AWS keys).


## 3. CLI Output
Update report to show:
- Rule ID + severity
- Platform-specific context
- File + line number
- Example:
```

❌ \[HIGH] Unpinned GitHub Action (GH001)
File: .github/workflows/build.yml:12
Rule: "Avoid using @master. Pin actions by commit SHA."

````


## 4. Deliverables
1. `rules/builtin.go` → Add expanded rules.
2. `scanner/engine.go` → Apply rules conditionally per platform.
3. `utils/platform.go` → Detect pipeline type from filename/path.
4. Unit tests for:
 - Each new regex rule
 - Platform detection logic
 - Mixed-pipeline repo (GitHub + GitLab files in same repo)


# Example Usage

$ cicd-guard scan --all
✅ Scanning 4 pipeline files...

❌ [HIGH] AWS Key detected (SEC001)
 File: azure-ci/deploy.yaml:20

⚠️ [MEDIUM] GitHub Action unpinned (GH001)
 File: .github/workflows/build.yml:12

⚠️ [MEDIUM] GitLab default branch set to "master" (GL001)
 File: .gitlab-ci.yml:3

