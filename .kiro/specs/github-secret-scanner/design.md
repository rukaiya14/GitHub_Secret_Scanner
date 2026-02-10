# Design Document: GitHub Secret Scanner

## Overview

The GitHub Secret Scanner is a lightweight, production-ready system for detecting leaked secrets in code repositories. It operates purely at inference time using regex-based pattern matching, without requiring any ML model training or GPU resources. The system integrates seamlessly with GitHub Actions to provide automated secret detection in CI/CD pipelines.

### Key Design Principles

1. **Zero Training Required**: All detection logic uses pre-defined regex patterns stored in a configuration file
2. **CI-Friendly Performance**: Fast execution (< 60 seconds for typical repos), low memory footprint (< 512MB)
3. **Deterministic Behavior**: Consistent results across runs, no randomness or model inference variability
4. **Clear Pass/Fail Signals**: Exit codes control pipeline behavior, blocking merges when secrets are detected
5. **Security by Default**: Masks secrets in logs, validates inputs, prevents common vulnerabilities

## Architecture

### System Components

```
┌─────────────────────────────────────────────────────────────┐
│                     GitHub Actions Workflow                  │
│  (Triggers on push/PR, sets up environment, runs scanner)   │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                    Secret Scanner (Python)                   │
│                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌─────────────────┐  │
│  │ Rule Loader  │  │ File Scanner │  │ Result Reporter │  │
│  │              │  │              │  │                 │  │
│  │ - Load XLSX  │  │ - Git diff   │  │ - Format output │  │
│  │ - Parse      │  │ - Apply      │  │ - Mask secrets  │  │
│  │   patterns   │  │   patterns   │  │ - Exit codes    │  │
│  └──────┬───────┘  └──────┬───────┘  └────────┬────────┘  │
│         │                  │                    │           │
│         └──────────────────┼────────────────────┘           │
│                            │                                │
│                   ┌────────▼────────┐                       │
│                   │ Validator       │                       │
│                   │                 │                       │
│                   │ - Placeholder   │                       │
│                   │   filtering     │                       │
│                   │ - Entropy check │                       │
│                   │ - Comment filter│                       │
│                   └─────────────────┘                       │
└─────────────────────────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                   Secret Rules File (XLSX)                   │
│  Columns: secret_type, pattern, description, confidence     │
└─────────────────────────────────────────────────────────────┘
```

### Data Flow

1. **Initialization**: Scanner loads regex patterns from `secret_rules.xlsx`
2. **File Discovery**: Scanner determines which files to scan based on mode (PR vs push)
3. **Pattern Matching**: For each file, apply all regex patterns line-by-line
4. **Validation**: Filter out placeholders, check entropy, optionally skip comments
5. **Classification**: Mark findings as HIGH or LOW confidence
6. **Reporting**: Print findings with masked secrets, return appropriate exit code
7. **Pipeline Control**: GitHub Actions interprets exit code to pass/fail the workflow

## Components and Interfaces

### 1. Rule Loader

**Responsibility**: Load and parse secret detection rules from the configuration file.

**Interface**:
```python
class RuleLoader:
    def load_rules(file_path: str) -> List[SecretRule]:
        """
        Load secret detection rules from XLSX/CSV file.
        
        Args:
            file_path: Path to the rules file
            
        Returns:
            List of SecretRule objects with compiled regex patterns
            
        Raises:
            FileNotFoundError: If rules file doesn't exist
            ValueError: If rules file is malformed
        """
```

**Implementation Notes**:
- Use pandas to read XLSX/CSV files
- Compile regex patterns at load time for performance
- Validate that required columns exist (secret_type, pattern, description, confidence_level)
- Handle regex compilation errors gracefully with clear error messages

### 2. File Scanner

**Responsibility**: Discover files to scan and apply detection patterns.

**Interface**:
```python
class FileScanner:
    def get_files_to_scan(mode: str, base_ref: str = None) -> List[str]:
        """
        Determine which files to scan based on mode.
        
        Args:
            mode: 'pull_request' or 'push'
            base_ref: Base branch for PR diffs (optional)
            
        Returns:
            List of file paths to scan
        """
    
    def scan_file(file_path: str, rules: List[SecretRule]) -> List[Finding]:
        """
        Scan a single file for secrets.
        
        Args:
            file_path: Path to file to scan
            rules: List of detection rules to apply
            
        Returns:
            List of Finding objects for detected secrets
        """
```

**Implementation Notes**:
- Use subprocess to run `git diff --name-only` for PR mode
- Use `os.walk()` or `pathlib.Path.rglob()` for push mode
- Skip binary files, large files (> 1MB), and common exclusions (.git, node_modules, etc.)
- Apply timeout per file (5 seconds) to prevent hanging
- Read files line-by-line to handle large files efficiently

### 3. Validator

**Responsibility**: Filter false positives and classify confidence levels.

**Interface**:
```python
class Validator:
    def is_placeholder(candidate: str) -> bool:
        """
        Check if a candidate string is a placeholder value.
        
        Args:
            candidate: The matched string to validate
            
        Returns:
            True if the string is a placeholder, False otherwise
        """
    
    def calculate_entropy(text: str) -> float:
        """
        Calculate Shannon entropy of a string.
        
        Args:
            text: String to analyze
            
        Returns:
            Entropy value (0.0 to 8.0 for byte strings)
        """
    
    def is_comment(line: str, file_extension: str) -> bool:
        """
        Check if a line is a comment based on file type.
        
        Args:
            line: Line of text to check
            file_extension: File extension (.py, .js, etc.)
            
        Returns:
            True if the line is a comment, False otherwise
        """
    
    def classify_confidence(finding: Finding, entropy_threshold: float = 3.5) -> str:
        """
        Classify a finding as HIGH or LOW confidence.
        
        Args:
            finding: The finding to classify
            entropy_threshold: Minimum entropy for HIGH confidence
            
        Returns:
            'HIGH' or 'LOW'
        """
```

**Implementation Notes**:
- Placeholder patterns: `(DUMMY|YOUR_KEY|XXXXX|SAMPLE|EXAMPLE|TEST|PLACEHOLDER|<.*>|\\{.*\\})`
- Entropy calculation: Shannon entropy using character frequency
- Comment detection: Support Python (#), JavaScript (//), Java (//), and multi-line comments (/* */)
- Default entropy threshold: 3.5 (configurable)

### 4. Result Reporter

**Responsibility**: Format and display scan results, control exit codes.

**Interface**:
```python
class ResultReporter:
    def mask_secret(secret: str, mask_percentage: float = 0.5) -> str:
        """
        Mask a portion of a secret string for safe logging.
        
        Args:
            secret: The secret string to mask
            mask_percentage: Percentage of characters to mask (0.0 to 1.0)
            
        Returns:
            Masked string with asterisks replacing characters
        """
    
    def print_findings(findings: List[Finding]) -> None:
        """
        Print all findings in a human-readable format.
        
        Args:
            findings: List of findings to display
        """
    
    def get_exit_code(findings: List[Finding]) -> int:
        """
        Determine exit code based on findings.
        
        Args:
            findings: List of findings
            
        Returns:
            0 if no HIGH confidence secrets, 1 otherwise
        """
```

**Implementation Notes**:
- Mask at least 50% of secret characters (e.g., "ghp_abc123xyz" → "ghp_***123***")
- Use emojis for visual clarity: 🚨 for failures, ✅ for success
- Print summary: "Found X high-confidence secrets in Y files"
- Group findings by file for better readability

### 5. Main Scanner Orchestrator

**Responsibility**: Coordinate all components and execute the scan workflow.

**Interface**:
```python
def main(
    mode: str = 'pull_request',
    rules_file: str = 'secret_rules.xlsx',
    base_ref: str = None,
    enable_entropy: bool = True,
    filter_comments: bool = True
) -> int:
    """
    Main entry point for the secret scanner.
    
    Args:
        mode: Scan mode ('pull_request' or 'push')
        rules_file: Path to rules configuration file
        base_ref: Base branch for PR diffs
        enable_entropy: Whether to use entropy filtering
        filter_comments: Whether to skip comments
        
    Returns:
        Exit code (0 for success, 1 for failure)
    """
```

**Implementation Notes**:
- Use argparse for command-line argument parsing
- Provide sensible defaults for all parameters
- Handle exceptions gracefully with clear error messages
- Log progress with tqdm if available (optional)

## Data Models

### SecretRule

Represents a single detection rule loaded from the configuration file.

```python
@dataclass
class SecretRule:
    secret_type: str          # e.g., "AWS Access Key", "GitHub Token"
    pattern: str              # Raw regex pattern string
    compiled_pattern: Pattern # Compiled regex object
    description: str          # Human-readable description
    confidence_level: str     # 'HIGH' or 'LOW' (from config)
```

### Finding

Represents a detected secret candidate.

```python
@dataclass
class Finding:
    file_path: str           # Relative path to file
    line_number: int         # Line number (1-indexed)
    matched_text: str        # The actual matched string
    secret_type: str         # Type from the rule
    confidence: str          # 'HIGH' or 'LOW' (after validation)
    entropy: float           # Shannon entropy value
    is_comment: bool         # Whether found in a comment
```

### ScanResult

Aggregates all findings from a scan.

```python
@dataclass
class ScanResult:
    findings: List[Finding]           # All detected findings
    files_scanned: int                # Total files processed
    high_confidence_count: int        # Count of HIGH confidence findings
    low_confidence_count: int         # Count of LOW confidence findings
    execution_time_seconds: float     # Total scan duration
```

## Correctness Properties

*A property is a characteristic or behavior that should hold true across all valid executions of a system—essentially, a formal statement about what the system should do. Properties serve as the bridge between human-readable specifications and machine-verifiable correctness guarantees.*

### Property 1: Pattern Application Completeness

*For any* file and any set of detection rules, when the Scanner processes the file, every regex pattern from every rule should be applied to every line in the file, and all matches should be extracted as candidate secrets.

**Validates: Requirements 1.2, 1.3**

### Property 2: Finding Data Completeness

*For any* detected candidate secret, the resulting Finding object should contain all required fields: file_path (non-empty), line_number (positive integer), matched_text (non-empty), secret_type (non-empty), and confidence (either 'HIGH' or 'LOW').

**Validates: Requirements 1.4, 5.4**

### Property 3: Placeholder Filtering

*For any* candidate secret that contains common placeholder patterns (DUMMY, YOUR_KEY, XXXXX, SAMPLE, EXAMPLE, TEST, PLACEHOLDER), the Scanner should exclude it from the final Detection_Findings list, regardless of what other patterns it matches.

**Validates: Requirements 2.1**

### Property 4: Case-Insensitive Placeholder Detection

*For any* placeholder pattern and any variation of that pattern with different casing (e.g., "dummy", "DUMMY", "Dummy"), the Scanner should treat them all equivalently and filter them all out.

**Validates: Requirements 2.3**

### Property 5: Comment Detection Across File Types

*For any* file with a recognized extension (.py, .js, .ts, .java, etc.), lines that start with the appropriate comment syntax for that file type (# for Python, // for JavaScript/TypeScript/Java) should be correctly identified as comments.

**Validates: Requirements 3.1, 3.2**

### Property 6: Comment Filtering Configuration

*For any* candidate secret found in a comment line, when filter_comments is enabled, the finding should be excluded from results; when filter_comments is disabled, the finding should be included in results.

**Validates: Requirements 3.3**

### Property 7: Entropy-Based Confidence Classification

*For any* candidate secret that passes placeholder filtering, when entropy-based filtering is enabled, if the Shannon entropy of the candidate is below the configured threshold, the confidence level should be 'LOW'; otherwise, it should be 'HIGH'.

**Validates: Requirements 5.1, 5.2, 5.3**

### Property 8: Secret Masking Percentage

*For any* secret string being logged or displayed, at least 50% of the characters should be replaced with mask characters (e.g., asterisks), ensuring that full credentials are never exposed in output.

**Validates: Requirements 7.2, 11.1**

### Property 9: Output Completeness

*For any* scan execution that produces findings, the output should include: each finding's file path, line number, and secret type; a summary count of total findings; and a clear pass/fail indicator.

**Validates: Requirements 7.1, 7.4**

### Property 10: Rules File Parsing Completeness

*For any* valid Secret_Rules_File with N rows of rules, the Scanner should successfully parse and compile all N regex patterns, making them available for detection.

**Validates: Requirements 9.3**

### Property 11: Deterministic Execution

*For any* repository and set of detection rules, running the Scanner multiple times with the same inputs should produce identical results in the same order (same findings, same order, same confidence levels).

**Validates: Requirements 10.4**

### Property 12: Path Traversal Prevention

*For any* file path input that contains directory traversal sequences (../, ..\, or absolute paths outside the repository), the Scanner should either reject the path or normalize it to prevent accessing files outside the intended scan scope.

**Validates: Requirements 11.3**

## Error Handling

### Error Categories

1. **Configuration Errors**
   - Missing or malformed rules file
   - Invalid regex patterns in rules
   - Missing required columns in rules file
   - **Handling**: Exit with code 2, print clear error message indicating the problem

2. **File System Errors**
   - File not found during scan
   - Permission denied reading file
   - File too large (> 1MB)
   - **Handling**: Log warning, skip file, continue scanning other files

3. **Git Errors**
   - Git not available in environment
   - Not in a git repository
   - Unable to determine changed files
   - **Handling**: In PR mode, fall back to scanning all files; log warning

4. **Regex Errors**
   - Pattern causes catastrophic backtracking (ReDoS)
   - Pattern takes too long to execute
   - **Handling**: Apply per-file timeout (5 seconds), skip file if timeout exceeded

5. **Resource Errors**
   - Out of memory
   - Disk space issues
   - **Handling**: Exit gracefully with error code 2, print diagnostic information

### Error Handling Principles

- **Fail Fast for Configuration**: If rules can't be loaded, exit immediately
- **Fail Soft for Individual Files**: If one file fails, continue with others
- **Clear Error Messages**: Always explain what went wrong and how to fix it
- **Distinct Exit Codes**: 0 = success, 1 = secrets found, 2 = error/failure
- **No Silent Failures**: Always log errors, never swallow exceptions without reporting

### Timeout Strategy

To prevent ReDoS and hanging on large files:

```python
def scan_file_with_timeout(file_path: str, rules: List[SecretRule], timeout: int = 5) -> List[Finding]:
    """
    Scan a file with a timeout to prevent hanging.
    
    Uses signal.alarm() on Unix or threading.Timer on Windows.
    If timeout is exceeded, returns empty list and logs warning.
    """
```

## Testing Strategy

### Dual Testing Approach

The Scanner will be validated using both unit tests and property-based tests:

- **Unit tests**: Verify specific examples, edge cases, and error conditions
- **Property tests**: Verify universal properties across all inputs
- Together, these provide comprehensive coverage: unit tests catch concrete bugs, property tests verify general correctness

### Property-Based Testing Configuration

**Library**: Use `hypothesis` for Python property-based testing

**Configuration**:
- Minimum 100 iterations per property test (due to randomization)
- Each property test must reference its design document property
- Tag format: `# Feature: github-secret-scanner, Property {number}: {property_text}`

**Example Property Test Structure**:
```python
from hypothesis import given, strategies as st

@given(
    file_content=st.text(min_size=1),
    rules=st.lists(st.builds(SecretRule, ...))
)
def test_property_1_pattern_application_completeness(file_content, rules):
    """
    Feature: github-secret-scanner, Property 1: Pattern Application Completeness
    
    For any file and any set of detection rules, when the Scanner processes 
    the file, every regex pattern from every rule should be applied to every 
    line in the file, and all matches should be extracted as candidate secrets.
    """
    # Test implementation
```

### Unit Testing Focus Areas

Unit tests should focus on:

1. **Specific Examples**:
   - Known secret patterns (AWS keys, GitHub tokens, etc.)
   - Known placeholder patterns
   - Specific file types and comment styles

2. **Edge Cases**:
   - Empty files
   - Files with no secrets
   - Files with only placeholders
   - Very long lines
   - Binary files
   - Files with special characters

3. **Error Conditions**:
   - Missing rules file
   - Malformed rules file
   - Invalid regex patterns
   - File permission errors
   - Git command failures

4. **Integration Points**:
   - CLI argument parsing
   - Exit code behavior
   - Output formatting
   - GitHub Actions workflow (in CI environment)

### Test Data

**Sample Rules File** (secret_rules.xlsx):
```
secret_type          | pattern                                    | description                | confidence_level
---------------------|--------------------------------------------|-----------------------------|------------------
AWS Access Key       | AKIA[0-9A-Z]{16}                          | AWS Access Key ID          | HIGH
GitHub Token         | ghp_[a-zA-Z0-9]{36}                       | GitHub Personal Access Token| HIGH
Generic API Key      | api[_-]?key[_-]?[=:]\s*['\"]?([a-zA-Z0-9]{32,})['\"]? | Generic API Key | HIGH
Private Key          | -----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY----- | Private Key File | HIGH
Slack Token          | xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[a-zA-Z0-9]{24,32} | Slack Token | HIGH
```

### Performance Testing

While not part of automated tests, manual performance validation should verify:
- Scan completes in < 60 seconds for 1000 files
- Memory usage stays under 512MB
- No CPU spikes or hanging on large files

### CI Integration Testing

The GitHub Actions workflow itself should be tested by:
- Creating test PRs with known secrets
- Verifying the workflow fails (exit code 1)
- Creating test PRs without secrets
- Verifying the workflow passes (exit code 0)
