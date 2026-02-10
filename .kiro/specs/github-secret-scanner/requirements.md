# Requirements Document

## Introduction

This document specifies the requirements for a production-ready real-time GitHub Secret Leak Detection system. The system detects real secrets (API keys, tokens, credentials, private keys) in GitHub code and issue text during pull requests and pushes, blocking merges when secrets are found. The system operates purely at inference time without any model training, using regex-based pattern matching and optional entropy filtering.

## Glossary

- **Scanner**: The Python-based secret detection engine that processes files and applies detection rules
- **Secret_Rules_File**: An Excel/CSV file containing regex patterns and metadata for detecting different types of secrets
- **High_Confidence_Secret**: A detected string that matches a secret pattern and passes validation checks (not a placeholder, has sufficient entropy)
- **Placeholder**: A fake or example value (e.g., DUMMY, YOUR_KEY, XXXXX, SAMPLE) that should not trigger detection
- **CI_Pipeline**: The GitHub Actions workflow that executes the Scanner on code changes
- **Exit_Code**: A numeric value returned by the Scanner to indicate success (0) or failure (1)
- **Changed_Files**: Files modified in a pull request or push event
- **Detection_Finding**: A record containing file name, line number, matched string, and secret type for a detected secret

## Requirements

### Requirement 1: Secret Pattern Detection

**User Story:** As a security engineer, I want to detect secrets using regex patterns, so that I can identify leaked credentials without training ML models.

#### Acceptance Criteria

1. WHEN the Scanner starts, THE Scanner SHALL load regex patterns from the Secret_Rules_File
2. WHEN processing a file, THE Scanner SHALL apply all regex patterns to each line of text
3. WHEN a regex pattern matches, THE Scanner SHALL extract the matched string as a candidate secret
4. WHEN a candidate secret is extracted, THE Scanner SHALL record the file name, line number, matched string, and secret type
5. THE Scanner SHALL support detection of API keys, tokens, credentials, and private keys through configurable patterns

### Requirement 2: Placeholder Filtering

**User Story:** As a developer, I want the system to ignore placeholder values, so that example code and documentation don't trigger false positives.

#### Acceptance Criteria

1. WHEN a candidate secret contains common placeholder patterns (DUMMY, YOUR_KEY, XXXXX, SAMPLE, EXAMPLE, TEST, PLACEHOLDER), THE Scanner SHALL exclude it from Detection_Findings
2. WHEN a candidate secret is all uppercase or contains repeated characters, THE Scanner SHALL apply additional validation before reporting
3. THE Scanner SHALL use case-insensitive matching for placeholder detection

### Requirement 3: Comment Filtering

**User Story:** As a developer, I want secrets in comments to be ignored where possible, so that documented examples don't cause false alarms.

#### Acceptance Criteria

1. WHEN scanning Python files, THE Scanner SHALL identify lines starting with # as comments
2. WHEN scanning JavaScript/TypeScript files, THE Scanner SHALL identify lines starting with // as comments
3. WHEN a candidate secret is found in a comment line, THE Scanner SHALL optionally exclude it based on configuration

### Requirement 4: File Scope Selection

**User Story:** As a DevOps engineer, I want to scan only changed files in pull requests, so that the CI pipeline runs quickly.

#### Acceptance Criteria

1. WHEN running in pull request mode, THE Scanner SHALL process only Changed_Files
2. WHEN running in push mode, THE Scanner SHALL process all repository files
3. WHEN determining Changed_Files, THE Scanner SHALL use git diff to identify modified files
4. THE Scanner SHALL accept a command-line argument to specify scan mode (pull_request or push)

### Requirement 5: High-Confidence Detection

**User Story:** As a security engineer, I want to distinguish high-confidence secrets from low-confidence matches, so that I can block merges only for real leaks.

#### Acceptance Criteria

1. WHEN a candidate secret passes placeholder filtering, THE Scanner SHALL classify it as a High_Confidence_Secret
2. WHEN entropy-based filtering is enabled, THE Scanner SHALL calculate the Shannon entropy of the candidate secret
3. IF entropy is below a configurable threshold, THEN THE Scanner SHALL downgrade the confidence level
4. THE Scanner SHALL mark each Detection_Finding with a confidence level (HIGH or LOW)

### Requirement 6: Pipeline Control

**User Story:** As a DevOps engineer, I want the CI pipeline to fail when secrets are detected, so that code with leaks cannot be merged.

#### Acceptance Criteria

1. WHEN at least one High_Confidence_Secret is found, THE Scanner SHALL print "🚨 SECRET DETECTED" and exit with Exit_Code 1
2. WHEN no High_Confidence_Secret is found, THE Scanner SHALL print "✅ No secrets detected" and exit with Exit_Code 0
3. THE CI_Pipeline SHALL interpret Exit_Code 1 as a failure and block the merge
4. THE CI_Pipeline SHALL interpret Exit_Code 0 as success and allow the merge

### Requirement 7: Output Formatting

**User Story:** As a developer, I want clear, human-readable output, so that I can quickly understand what secrets were found and where.

#### Acceptance Criteria

1. WHEN the Scanner finds secrets, THE Scanner SHALL print each Detection_Finding with file name, line number, and secret type
2. WHEN printing matched strings, THE Scanner SHALL mask portions of the secret to avoid logging full credentials
3. THE Scanner SHALL use clear visual indicators (emojis, colors) to distinguish success from failure
4. THE Scanner SHALL print a summary count of total findings at the end

### Requirement 8: GitHub Actions Integration

**User Story:** As a DevOps engineer, I want the Scanner to run automatically on pushes and pull requests, so that all code changes are checked for secrets.

#### Acceptance Criteria

1. WHEN code is pushed to the main branch, THE CI_Pipeline SHALL trigger the Scanner
2. WHEN a pull request is opened or updated, THE CI_Pipeline SHALL trigger the Scanner
3. THE CI_Pipeline SHALL check out the repository code before running the Scanner
4. THE CI_Pipeline SHALL set up Python 3.10 and install dependencies before running the Scanner
5. WHEN the Scanner exits with code 1, THE CI_Pipeline SHALL mark the workflow as failed

### Requirement 9: Configuration Management

**User Story:** As a security engineer, I want to manage detection rules in a spreadsheet, so that I can easily add or modify patterns without changing code.

#### Acceptance Criteria

1. THE Secret_Rules_File SHALL be stored in Excel (.xlsx) or CSV format
2. THE Secret_Rules_File SHALL contain columns for: secret_type, pattern (regex), description, confidence_level
3. WHEN the Scanner loads the Secret_Rules_File, THE Scanner SHALL parse all rows and compile regex patterns
4. IF the Secret_Rules_File is missing or malformed, THEN THE Scanner SHALL exit with an error message

### Requirement 10: Performance and Resource Constraints

**User Story:** As a DevOps engineer, I want the Scanner to run quickly and use minimal resources, so that it doesn't slow down the CI pipeline.

#### Acceptance Criteria

1. THE Scanner SHALL complete execution within 60 seconds for repositories with up to 1000 files
2. THE Scanner SHALL use no more than 512MB of memory during execution
3. THE Scanner SHALL not require GPU resources
4. THE Scanner SHALL process files sequentially to maintain deterministic behavior
5. WHEN scanning large files, THE Scanner SHALL apply a timeout of 5 seconds per file

### Requirement 11: Security Best Practices

**User Story:** As a security engineer, I want the Scanner to follow security best practices, so that it doesn't introduce new vulnerabilities.

#### Acceptance Criteria

1. WHEN logging Detection_Findings, THE Scanner SHALL mask at least 50% of the matched secret string
2. THE Scanner SHALL not write full secrets to disk or temporary files
3. THE Scanner SHALL validate all file paths to prevent directory traversal attacks
4. THE Scanner SHALL handle regex patterns safely to prevent ReDoS (Regular Expression Denial of Service) attacks

### Requirement 12: Dependency Management

**User Story:** As a developer, I want minimal, well-defined dependencies, so that the Scanner is easy to install and maintain.

#### Acceptance Criteria

1. THE Scanner SHALL depend only on: pandas, openpyxl, regex, and optionally tqdm
2. THE requirements.txt file SHALL specify exact or minimum versions for all dependencies
3. THE Scanner SHALL work with Python 3.10 or higher
4. THE Scanner SHALL not require compilation or system-level dependencies beyond Python packages
