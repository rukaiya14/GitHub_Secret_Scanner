# Implementation Plan: GitHub Secret Scanner

## Overview

This implementation plan breaks down the GitHub Secret Scanner into discrete, incremental coding tasks. Each task builds on previous work, with testing integrated throughout to validate functionality early. The plan follows a bottom-up approach: core data models → validation logic → file scanning → orchestration → CI integration.

## Tasks

- [x] 1. Set up project structure and dependencies
  - Create directory structure with scan_secrets.py at root
  - Create requirements.txt with: pandas>=2.0.0, openpyxl>=3.1.0, regex>=2023.0.0, hypothesis>=6.82.0 (for testing)
  - Create example secret_rules.xlsx with sample patterns (AWS keys, GitHub tokens, API keys, private keys)
  - Set up basic Python module structure with imports
  - _Requirements: 12.1, 12.2, 12.3, 12.4_

- [ ] 2. Implement core data models
  - [x] 2.1 Create SecretRule and Finding dataclasses
    - Define SecretRule with: secret_type, pattern, compiled_pattern, description, confidence_level
    - Define Finding with: file_path, line_number, matched_text, secret_type, confidence, entropy, is_comment
    - Define ScanResult with: findings, files_scanned, high_confidence_count, low_confidence_count, execution_time_seconds
    - _Requirements: 1.4, 5.4_
  
  - [x] 2.2 Write property test for Finding data completeness
    - **Property 2: Finding Data Completeness**
    - **Validates: Requirements 1.4, 5.4**

- [ ] 3. Implement RuleLoader component
  - [x] 3.1 Create RuleLoader class with load_rules method
    - Use pandas to read XLSX/CSV files
    - Validate required columns exist (secret_type, pattern, description, confidence_level)
    - Compile regex patterns using regex library
    - Handle FileNotFoundError and ValueError with clear error messages
    - Return list of SecretRule objects
    - _Requirements: 1.1, 9.1, 9.2, 9.3, 9.4_
  
  - [x] 3.2 Write property test for rules file parsing completeness
    - **Property 10: Rules File Parsing Completeness**
    - **Validates: Requirements 9.3**
  
  - [x] 3.3 Write unit tests for RuleLoader
    - Test loading valid XLSX file
    - Test loading valid CSV file
    - Test error handling for missing file
    - Test error handling for malformed file (missing columns)
    - Test error handling for invalid regex patterns
    - _Requirements: 9.1, 9.2, 9.4_

- [ ] 4. Implement Validator component
  - [x] 4.1 Create Validator class with placeholder detection
    - Implement is_placeholder method with regex for common patterns
    - Use case-insensitive matching
    - Patterns: DUMMY, YOUR_KEY, XXXXX, SAMPLE, EXAMPLE, TEST, PLACEHOLDER, <.*>, \{.*\}
    - _Requirements: 2.1, 2.3_
  
  - [x] 4.2 Implement entropy calculation
    - Create calculate_entropy method using Shannon entropy formula
    - Handle empty strings and edge cases
    - _Requirements: 5.2_
  
  - [x] 4.3 Implement comment detection
    - Create is_comment method that checks file extension
    - Support Python (#), JavaScript/TypeScript (//), Java (//)
    - Handle leading whitespace before comment markers
    - _Requirements: 3.1, 3.2_
  
  - [x] 4.4 Implement confidence classification
    - Create classify_confidence method
    - Check if candidate passes placeholder filter
    - Calculate entropy and compare to threshold (default 3.5)
    - Return 'HIGH' or 'LOW'
    - _Requirements: 5.1, 5.2, 5.3_
  
  - [x] 4.5 Write property test for placeholder filtering
    - **Property 3: Placeholder Filtering**
    - **Validates: Requirements 2.1**
  
  - [x] 4.6 Write property test for case-insensitive placeholder detection
    - **Property 4: Case-Insensitive Placeholder Detection**
    - **Validates: Requirements 2.3**
  
  - [x] 4.7 Write property test for comment detection
    - **Property 5: Comment Detection Across File Types**
    - **Validates: Requirements 3.1, 3.2**
  
  - [x] 4.8 Write property test for entropy-based confidence classification
    - **Property 7: Entropy-Based Confidence Classification**
    - **Validates: Requirements 5.1, 5.2, 5.3**
  
  - [x] 4.9 Write unit tests for Validator edge cases
    - Test empty strings
    - Test very long strings
    - Test special characters
    - Test various file extensions
    - _Requirements: 2.1, 2.3, 3.1, 3.2, 5.1, 5.2, 5.3_

- [x] 5. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 6. Implement FileScanner component
  - [x] 6.1 Create FileScanner class with file discovery
    - Implement get_files_to_scan method
    - For 'pull_request' mode: use subprocess to run 'git diff --name-only' against base ref
    - For 'push' mode: use pathlib.Path.rglob() to find all files
    - Exclude common directories: .git, node_modules, __pycache__, .venv, dist, build
    - Exclude binary files and files > 1MB
    - Handle git command errors gracefully (fall back to all files)
    - _Requirements: 4.1, 4.2, 4.3_
  
  - [x] 6.2 Implement file scanning with pattern matching
    - Create scan_file method that reads file line-by-line
    - Apply all regex patterns to each line
    - Extract matches and create Finding objects
    - Apply timeout per file (5 seconds) using signal or threading
    - Handle file read errors gracefully (log warning, continue)
    - _Requirements: 1.2, 1.3, 1.4, 10.5_
  
  - [x] 6.3 Integrate Validator into scanning pipeline
    - For each match, check if it's a placeholder
    - For each match, check if it's in a comment (if filter_comments enabled)
    - Calculate entropy and classify confidence
    - Only include non-placeholder, high-confidence findings in results
    - _Requirements: 2.1, 3.3, 5.1, 5.2, 5.3_
  
  - [x] 6.4 Write property test for pattern application completeness
    - **Property 1: Pattern Application Completeness**
    - **Validates: Requirements 1.2, 1.3**
  
  - [x] 6.5 Write property test for comment filtering configuration
    - **Property 6: Comment Filtering Configuration**
    - **Validates: Requirements 3.3**
  
  - [x] 6.6 Write property test for path traversal prevention
    - **Property 12: Path Traversal Prevention**
    - **Validates: Requirements 11.3**
  
  - [x] 6.7 Write unit tests for FileScanner
    - Test file discovery in PR mode
    - Test file discovery in push mode
    - Test scanning files with known secrets
    - Test scanning files with only placeholders
    - Test scanning empty files
    - Test timeout behavior on slow patterns
    - Test file exclusion logic
    - _Requirements: 4.1, 4.2, 4.3, 10.5_

- [ ] 7. Implement ResultReporter component
  - [x] 7.1 Create ResultReporter class with secret masking
    - Implement mask_secret method
    - Mask at least 50% of characters (default)
    - Preserve prefix for context (e.g., "ghp_" for GitHub tokens)
    - Replace masked characters with asterisks
    - _Requirements: 7.2, 11.1_
  
  - [x] 7.2 Implement findings output formatting
    - Create print_findings method
    - Group findings by file for readability
    - Print each finding with: file path, line number, masked secret, secret type
    - Use emojis for visual clarity (🚨 for secrets, ✅ for clean)
    - Print summary count at the end
    - _Requirements: 7.1, 7.3, 7.4_
  
  - [x] 7.3 Implement exit code logic
    - Create get_exit_code method
    - Return 1 if any HIGH confidence findings exist
    - Return 0 if no HIGH confidence findings
    - _Requirements: 6.1, 6.2_
  
  - [x] 7.4 Write property test for secret masking percentage
    - **Property 8: Secret Masking Percentage**
    - **Validates: Requirements 7.2, 11.1**
  
  - [x] 7.5 Write property test for output completeness
    - **Property 9: Output Completeness**
    - **Validates: Requirements 7.1, 7.4**
  
  - [x] 7.6 Write unit tests for ResultReporter
    - Test masking various secret formats
    - Test output formatting with multiple findings
    - Test exit code with HIGH confidence findings
    - Test exit code with no findings
    - Test exit code with only LOW confidence findings
    - _Requirements: 6.1, 6.2, 7.1, 7.2, 7.3, 7.4, 11.1_

- [x] 8. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 9. Implement main Scanner orchestrator
  - [x] 9.1 Create main function with CLI argument parsing
    - Use argparse to define arguments: --mode, --rules-file, --base-ref, --enable-entropy, --filter-comments
    - Set sensible defaults: mode='pull_request', rules_file='secret_rules.xlsx', enable_entropy=True, filter_comments=True
    - Add --help documentation for all arguments
    - _Requirements: 4.4_
  
  - [x] 9.2 Implement main scan workflow
    - Load rules using RuleLoader
    - Discover files using FileScanner
    - Scan each file and collect findings
    - Track execution time and file count
    - Create ScanResult object
    - Handle exceptions gracefully with clear error messages
    - Use distinct exit codes: 0=success, 1=secrets found, 2=error
    - _Requirements: 1.1, 4.1, 4.2, 10.1, 10.2, 10.3, 10.4_
  
  - [x] 9.3 Wire all components together
    - Instantiate RuleLoader, FileScanner, Validator, ResultReporter
    - Pass configuration through the pipeline
    - Ensure deterministic execution (sequential file processing)
    - Print findings using ResultReporter
    - Return appropriate exit code
    - _Requirements: 10.4_
  
  - [x] 9.4 Write property test for deterministic execution
    - **Property 11: Deterministic Execution**
    - **Validates: Requirements 10.4**
  
  - [x] 9.5 Write integration tests for main workflow
    - Test end-to-end scan with known secrets
    - Test end-to-end scan with no secrets
    - Test end-to-end scan with only placeholders
    - Test CLI argument parsing
    - Test error handling for missing rules file
    - Test error handling for git errors
    - _Requirements: 1.1, 4.1, 4.2, 4.4, 9.4_

- [ ] 10. Create GitHub Actions workflow
  - [x] 10.1 Create .github/workflows/secret-scan.yml
    - Configure triggers: on push to main, on pull_request
    - Add job steps: checkout repository, setup Python 3.10, install dependencies, run scanner
    - Pass appropriate arguments based on event type (PR vs push)
    - For PRs: use --mode=pull_request --base-ref=${{ github.base_ref }}
    - For pushes: use --mode=push
    - Ensure workflow fails if scanner exits with code 1
    - _Requirements: 8.1, 8.2, 8.3, 8.4, 8.5_
  
  - [x] 10.2 Write unit test for workflow file validation
    - Verify YAML syntax is valid
    - Verify required steps are present
    - Verify triggers are configured correctly
    - _Requirements: 8.1, 8.2, 8.3, 8.4_

- [ ] 11. Add documentation and examples
  - [x] 11.1 Add inline comments to scan_secrets.py
    - Document each class and method with docstrings
    - Explain key logic decisions (placeholder patterns, entropy threshold, etc.)
    - Add usage examples in module docstring
    - _Requirements: All_
  
  - [x] 11.2 Create example secret_rules.xlsx with comprehensive patterns
    - Include patterns for: AWS keys, GitHub tokens, Slack tokens, API keys, private keys, database URLs
    - Add descriptions for each pattern
    - Set appropriate confidence levels
    - _Requirements: 1.5, 9.1, 9.2_
  
  - [x] 11.3 Add README section with usage instructions
    - Document CLI arguments
    - Provide example commands
    - Explain exit codes
    - Show example output
    - _Requirements: All_

- [x] 12. Final checkpoint - Ensure all tests pass
  - Run full test suite with property tests (100+ iterations each)
  - Verify all unit tests pass
  - Verify integration tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation at key milestones
- Property tests validate universal correctness properties with 100+ iterations
- Unit tests validate specific examples, edge cases, and error conditions
- The implementation follows a bottom-up approach: data models → validation → scanning → orchestration → CI integration
- All code should include clear inline comments explaining logic and design decisions
