# ShardJacker - Elasticsearch Advanced Scanner & Exploitation Tool

A comprehensive Elasticsearch security assessment framework that performs reconnaissance through full exploitation testing. This tool supports multiple operational modes from passive discovery to active exploitation validation, making it suitable for both penetration testing reports and comprehensive security audits.

## Features

- **Multiple Operational Modes**:

  - Simple Write Test: Clean write/read-only testing for client reports
  - Reconnaissance: Passive discovery of accessible indices and clusters
  - Basic Testing: Traditional write permission testing with index limiting
  - Exploitation: Comprehensive attack capability validation

- **Advanced Protocol Detection**: Automatically detects HTTP/HTTPS with Elasticsearch validation
- **Thread-Safe Concurrent Scanning**: Configurable thread pool for performance optimization
- **Comprehensive Exploitation Testing**:
  - Document injection with multiple payload types
  - Document modification and deletion testing
  - Bulk operations testing
  - Index creation capability validation
- **Flexible Output Formats**: Console, JSON, and CSV export options
- **Authentication Support**: HTTP Basic authentication
- **Index Limiting**: Performance optimization for large deployments
- **Automatic Cleanup**: All test artifacts are cleaned up after testing

## Requirements

- Python 3.6+
- Required Python packages:
  - requests
  - urllib3

# Installation

### Clone or download the script

wget <https://example.com/shardjacker.py>
chmod +x shardjacker.py

### Install required dependencies

pip3 install requests urllib3

## Usage

### Basic Usage

### Simple write test for penetration testing reports

    python3 shardjacker.py -f targets.txt --write-test-only --csv-output pentest_results

### Basic reconnaissance mode

    python3 shardjacker.py -f targets.txt --recon-only

### Standard write permission testing

    python3 shardjacker.py -f targets.txt

### Full exploitation testing

    python3 shardjacker.py -f targets.txt --exploit-confirm

## Advanced Usage Examples

### Comprehensive write test with no index limit (for complete client reports)

    python3 shardjacker.py -f targets.txt --write-test-only --no-index-limit --csv-output client_report

### Silent mode for automated reporting

    python3 shardjacker.py -f targets.txt --write-test-only --no-console --csv-output automated_scan

#### Authenticated scanning with custom thread count

    python3 shardjacker.py -f targets.txt -u elastic -p changeme --threads 8 --timeout 20

### Selective exploitation testing

    python3 shardjacker.py -f targets.txt --exploit-confirm --exploit-types injection modification deletion

### Performance-optimized scan for large deployments

    python3 shardjacker.py -f targets.txt --max-indices 100 --threads 10 --timeout 30

## Configuration

Target File Format

Create a text file with one target per line in IP:PORT format:
    192.168.1.100:9200
    10.0.0.50:9200
    elasticsearch.example.com:9200

## Command Line Options

Required Arguments

    -f, --file: File containing Elasticsearch targets (required)

Authentication Options

    -u, --username: Username for HTTP Basic authentication
    -p, --password: Password for HTTP Basic authentication

Performance & Connection Options

    -t, --timeout: HTTP request timeout in seconds (default: 15)
    --threads: Number of concurrent scanning threads (default: 5, max recommended: 10)
    --max-indices: Maximum indices to test per target (default: 50)
    --no-index-limit: Remove index limit - test all indices

Operational Modes

    --write-test-only: Simple write test mode for penetration testing reports
    --recon-only: Reconnaissance mode - passive index discovery only
    --exploit-confirm: Enable comprehensive exploitation testing

Exploitation Options

    --exploit-types: Specify exploitation tests (choices: injection, modification, deletion, bulk, index_creation)
    --show-exploit-data: Display detailed exploitation data and curl commands

Output & Reporting Options

    -o, --output: Save detailed results to JSON file
    --csv-output: Export results to CSV files using specified prefix
    --show-read-only: Display read-only indices in console output
    --no-console: Suppress all console output (silent mode)

Processing Options

    --dedupe: Remove duplicate target+index combinations from results

# Output

Console Output

Real-time progress tracking with color-coded status indicators:

    - ✅ Successful operations
    - ❌ Errors and failures
    - 🔍 Discovery operations
    - 💥 Exploitation confirmations
    - 🔐 Authentication required

# JSON Output

## Structured output with scan metadata

### JSON

    {
      "scan_metadata": {
        "tool": "Elasticsearch Advanced Scanner & Exploitation Tool",
        "version": "2.0",
        "total_results": 150
      },
      "results": [
        {
          "target": "https://192.168.1.100:9200",
          "index": "user_data",
          "status": "writable",
          "method": "write_test"
        }
      ]
    }

### CSV Output

Multiple CSV files are generated:

- prefix_writable.csv: Writable indices
- prefix_readonly.csv: Read-only indices
- prefix_accessible.csv: Accessible indices (recon mode)
- prefix_exploit_confirmed.csv: Confirmed exploitable indices
- prefix_combined.csv: All results combined
  Exploitation Testing

When using --exploit-confirm, the tool performs comprehensive security testing:

Document Injection Testing

    Benign payloads: Standard test documents
    Log spoofing: Fake security alerts and error messages
    Malicious payloads: XSS and command injection attempts
    Command injection: System command execution attempts

Document Operations Testing

    Modification: Before/after tampering verification
    Deletion: Evidence removal capabilities
    Bulk operations: Mass data injection testing

Administrative Testing

    Index creation: Administrative control validation
    Privilege escalation: Permission boundary testing

All exploitation tests include:

- Automatic cleanup of test artifacts
- Curl command generation for manual reproduction
- Detailed verification of successful operations
  Performance Recommendations

      Use --write-test-only --no-index-limit for complete client reports (slow but comprehensive)
      Use --max-indices 10-50 for initial reconnaissance
      Use --max-indices 100-500 for comprehensive testing
      Use --max-indices 1000+ only for complete audits
      Increase --timeout when using higher --max-indices values
      Limit threads to 5-8 for stability with increased timeout

Security Considerations

    Simple write test mode performs minimal operations with immediate cleanup
    Exploitation mode performs actual write operations with verification
    All test artifacts are automatically cleaned up after testing
    SSL certificate verification disabled for testing environments
    Comprehensive logging of all operations
    Safe payload testing with immediate cleanup verification

# License

This tool is provided for authorized security testing purposes only. Users are responsible for ensuring they have proper authorization before testing any systems.

# Author

Created by Abira Security
