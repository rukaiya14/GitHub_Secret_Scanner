# GitHub Secret Scanner

A production-ready real-time GitHub Secret Leak Detection system that detects secrets (API keys, tokens, credentials, private keys) in GitHub code during pull requests and pushes, blocking merges when secrets are found.

## Features

- **Zero Training Required**: Uses regex-based pattern matching without ML models
- **Fast & Lightweight**: Scans 100 files in < 10 seconds, uses < 100MB memory
- **CI-Friendly**: Integrates seamlessly with GitHub Actions
- **Smart Filtering**: Automatically filters placeholders, low-entropy strings, and comments
- **Secure**: Masks secrets in output to prevent log exposure
- **Deterministic**: Consistent results across runs

## Installation

### Prerequisites

- Python 3.10 or higher
- Git (for pull request mode)

### Install Dependencies

```bash
pip install -r requirements.txt
```

Required packages:
- `pandas>=2.0.0` - For reading rules files
- `openpyxl>=3.1.0` - For XLSX support
- `regex>=2023.0.0` - Advanced regex engine

## Usage

### Basic Usage

**Scan changed files in a pull request (default mode):**
```bash
python scan_secrets.py --mode pull_request --base-ref main
```

**Scan all files in the repository:**
```bash
python scan_secrets.py --mode push
```

### CLI Arguments

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `--mode` | choice | `pull_request` | Scan mode: `pull_request` (changed files only) or `push` (all files) |
| `--rules-file` | string | `secret_rules.xlsx` | Path to rules configuration file (XLSX or CSV format) |
| `--base-ref` | string | `origin/main` | Base branch for pull request diffs (e.g., `main`, `master`, `develop`) |
| `--enable-entropy` | flag | enabled | Enable entropy-based filtering to reduce false positives |
| `--no-entropy` | flag | - | Disable entropy filtering (more aggressive scanning) |
| `--filter-comments` | flag | enabled | Filter out secrets found in code comments |
| `--no-filter-comments` | flag | - | Include secrets found in comments |

### Example Commands

**Scan with custom rules file:**
```bash
python scan_secrets.py --mode push --rules-file custom_rules.csv
```

**Disable entropy filtering (more aggressive):**
```bash
python scan_secrets.py --mode push --no-entropy
```

**Include secrets in comments:**
```bash
python scan_secrets.py --mode pull_request --no-filter-comments
```

**Combine multiple options:**
```bash
python scan_secrets.py --mode pull_request --base-ref develop --no-entropy --no-filter-comments
```

## Exit Codes

The scanner uses exit codes to control CI pipeline behavior:

| Exit Code | Meaning | Pipeline Behavior |
|-----------|---------|-------------------|
| `0` | No high-confidence secrets detected | ✅ **PASS** - Merge allowed |
| `1` | High-confidence secrets detected | ❌ **FAIL** - Merge blocked |
| `2` | Error occurred during execution | ❌ **FAIL** - Scanner error |

### Exit Code Examples

**Success (Exit Code 0):**
```
✅ No secrets detected
✅ No high-confidence secrets detected - pipeline will PASS
```

**Secrets Found (Exit Code 1):**
```
🚨 SECRET DETECTED - Found 2 potential secret(s) in 1 file(s)
   High confidence: 2, Low confidence: 0

📄 config.py
   🔴 Line 42: AWS Access Key
      Secret: AKIA***************
      Entropy: 4.23

❌ High-confidence secrets detected - pipeline will FAIL
```

**Error (Exit Code 2):**
```
❌ Error: Rules file not found: secret_rules.xlsx
Please ensure the rules file exists at the specified path.
```

## Example Output

### Clean Scan (No Secrets)

```
🔍 GitHub Secret Scanner
============================================================
Mode:              pull_request
Rules file:        secret_rules.xlsx
Base reference:    main
Entropy filtering: enabled
Comment filtering: enabled
============================================================

📋 Loading detection rules from secret_rules.xlsx...
✅ Loaded 5 detection rule(s)

🔎 Discovering files to scan (mode: pull_request)...
✅ Found 3 file(s) to scan

🔍 Scanning files for secrets...
✅ Scanned 3 file(s)

✅ No secrets detected

⏱️  Execution time: 0.42 seconds
📊 Files scanned: 3
🔍 Total findings: 0 (0 high, 0 low)

✅ No high-confidence secrets detected - pipeline will PASS
```

### Secrets Detected

```
🔍 GitHub Secret Scanner
============================================================
Mode:              push
Rules file:        secret_rules.xlsx
Entropy filtering: enabled
Comment filtering: enabled
============================================================

📋 Loading detection rules from secret_rules.xlsx...
✅ Loaded 5 detection rule(s)

🔎 Discovering files to scan (mode: push)...
✅ Found 127 file(s) to scan

🔍 Scanning files for secrets...
✅ Scanned 127 file(s)

🚨 SECRET DETECTED - Found 3 potential secret(s) in 2 file(s)
   High confidence: 2, Low confidence: 1

📄 config.py
   🔴 Line 42: AWS Access Key
      Secret: AKIA***************
      Entropy: 4.23

   🔴 Line 58: GitHub Token
      Secret: ghp_***************************
      Entropy: 4.87

📄 settings.json
   🟡 Line 15: Generic API Key
      Secret: api_key_***********
      Entropy: 3.12

============================================================
Summary: 2 high-confidence secret(s) detected
⚠️  Pipeline will FAIL - secrets must be removed before merge
============================================================

⏱️  Execution time: 2.15 seconds
📊 Files scanned: 127
🔍 Total findings: 3 (2 high, 1 low)

❌ High-confidence secrets detected - pipeline will FAIL
```

## GitHub Actions Integration

### Workflow Configuration

Create `.github/workflows/secret-scan.yml`:

```yaml
name: Secret Scanner

on:
  push:
    branches: [ main, master ]
  pull_request:
    branches: [ main, master ]

jobs:
  scan-secrets:
    runs-on: ubuntu-latest
    
    steps:
      - name: Checkout repository
        uses: actions/checkout@v3
        with:
          fetch-depth: 0  # Fetch all history for git diff
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.10'
      
      - name: Install dependencies
        run: |
          pip install -r requirements.txt
      
      - name: Scan for secrets (Pull Request)
        if: github.event_name == 'pull_request'
        run: |
          python scan_secrets.py --mode pull_request --base-ref ${{ github.base_ref }}
      
      - name: Scan for secrets (Push)
        if: github.event_name == 'push'
        run: |
          python scan_secrets.py --mode push
```

### How It Works

1. **On Pull Request**: Scans only changed files for fast feedback
2. **On Push**: Scans all files for comprehensive coverage
3. **Merge Blocking**: If secrets are detected (exit code 1), the workflow fails and blocks the merge
4. **Status Checks**: GitHub shows the workflow status on the PR, preventing merge until secrets are removed

## Configuration

### Rules File Format

The scanner uses an XLSX or CSV file to define detection patterns. The file must contain these columns:

| Column | Type | Description | Example |
|--------|------|-------------|---------|
| `secret_type` | string | Name of the secret type | `AWS Access Key` |
| `pattern` | regex | Regular expression pattern | `AKIA[0-9A-Z]{16}` |
| `description` | string | Human-readable description | `AWS Access Key ID` |
| `confidence_level` | string | `HIGH` or `LOW` | `HIGH` |

### Example Rules File

**secret_rules.xlsx:**

| secret_type | pattern | description | confidence_level |
|-------------|---------|-------------|------------------|
| AWS Access Key | `AKIA[0-9A-Z]{16}` | AWS Access Key ID | HIGH |
| GitHub Token | `ghp_[a-zA-Z0-9]{36}` | GitHub Personal Access Token | HIGH |
| Generic API Key | `api[_-]?key[_-]?[=:]\s*['\"]?([a-zA-Z0-9]{32,})['\"]?` | Generic API Key | HIGH |
| Private Key | `-----BEGIN (RSA\|DSA\|EC\|OPENSSH) PRIVATE KEY-----` | Private Key File | HIGH |
| Slack Token | `xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[a-zA-Z0-9]{24,32}` | Slack Token | HIGH |

### Customizing Detection

**Add new secret patterns:**
1. Open `secret_rules.xlsx` in Excel or a spreadsheet editor
2. Add a new row with your pattern
3. Save the file
4. Run the scanner - new patterns are automatically loaded

**Adjust entropy threshold:**
Edit `scan_secrets.py` and modify the `entropy_threshold` parameter in the `main()` function (default: 3.5).

## How It Works

### Detection Pipeline

```
Rules File → RuleLoader → FileScanner → Validator → ResultReporter → Exit Code
                              ↓
                         Git Diff (PR mode)
                         or All Files (Push mode)
```

### Filtering Strategy

The scanner applies multiple filters to reduce false positives:

1. **Placeholder Detection**: Filters common placeholder patterns
   - `DUMMY`, `YOUR_KEY`, `XXXXX`, `SAMPLE`, `EXAMPLE`, `TEST`, `PLACEHOLDER`
   - `<YOUR_KEY_HERE>`, `{API_KEY}` (template syntax)

2. **Entropy Filtering**: Calculates Shannon entropy to detect randomness
   - Real secrets typically have entropy > 4.0 (random-looking)
   - Placeholders often have entropy < 3.5 (patterns, repetition)
   - Default threshold: 3.5 (configurable)

3. **Comment Filtering**: Optionally skips secrets in code comments
   - Supports Python (`#`), JavaScript/TypeScript (`//`), Java (`//`)
   - Reduces false positives from documentation and example code

### Security Features

- **Secret Masking**: At least 50% of each secret is masked in output
  - Example: `ghp_abc123xyz789` → `ghp_***123***789`
- **No Disk Writes**: Secrets are never written to disk or temporary files
- **Path Validation**: File paths are validated to prevent directory traversal
- **Timeout Protection**: 5-second timeout per file prevents ReDoS attacks

## Performance

- **Typical scan time**: < 10 seconds for 100 files
- **Memory usage**: < 100MB for typical repositories
- **Scales linearly**: Performance scales with number of files and patterns
- **No GPU required**: Pure CPU-based processing

## Troubleshooting

### Common Issues

**Issue: "Rules file not found"**
```
❌ Error: Rules file not found: secret_rules.xlsx
```
**Solution**: Ensure `secret_rules.xlsx` exists in the current directory or specify the correct path with `--rules-file`.

---

**Issue: "Git command failed"**
```
⚠️  Git command failed: ...
⚠️  Falling back to scanning all files
```
**Solution**: This is a warning, not an error. The scanner automatically falls back to scanning all files. Ensure you're in a git repository and git is installed.

---

**Issue: "No files to scan"**
```
ℹ️  No files to scan
✅ No secrets detected
```
**Solution**: This can happen if:
- All changed files are binary or excluded
- No files match the scan criteria
- The PR has no file changes

---

**Issue: False positives**
```
🔴 Line 42: Generic API Key
   Secret: api_key_***********
```
**Solution**: 
- Use `--no-filter-comments` if the secret is in a comment
- Adjust the entropy threshold in the code
- Update the regex pattern in `secret_rules.xlsx` to be more specific
- Add the pattern to the placeholder filter if it's a known false positive

## Contributing

### Adding New Secret Patterns

1. Research the secret format (e.g., AWS keys start with `AKIA`)
2. Create a regex pattern that matches the format
3. Test the pattern with real and fake examples
4. Add the pattern to `secret_rules.xlsx`
5. Run tests to ensure no regressions

### Running Tests

```bash
# Run all tests
pytest

# Run specific test file
pytest test_validator.py

# Run with coverage
pytest --cov=scan_secrets
```

## License

This project is provided as-is for educational and security purposes.

## Support

For issues, questions, or contributions, please refer to the project documentation or contact the development team.
