"""
LCS Retrieval V1 — Independent 100-Query Generalization Evaluation
==================================================================
Evaluates the frozen Capability Retrieval Engine V1 against an expanded
corpus of 40 capabilities across 7 independent servers without modifying
the retrieval implementation.

Harness Properties:
- Ground-truth defined strictly prior to evaluation.
- Categorized test cases:
  1. Direct Task Requests (25)
  2. Synonyms & Paraphrasing (20)
  3. Lexical Overlap Traps (15)
  4. Multi-Capability Requests (10)
  5. Ambiguous Requests (10)
  6. Out-of-Domain Requests (20)
- Computes:
  - Precision@1, Precision@3, Recall@3, MRR
  - Correct Abstention Rate, False-Positive Rate
  - Category-by-category breakdown
  - Comprehensive failure audit for every mispredicted or missed query
"""

import os
import sys
import json
import tempfile
from typing import Dict, Any, List, Set, Optional

# Ensure project root is importable
PROJ_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJ_ROOT not in sys.path:
    sys.path.insert(0, PROJ_ROOT)

from lcs.config import LCSConfig
from lcs.context import LCSContext
from lcs.policy import InterfaceTrustPolicy
from capability_retrieval_v1 import CapabilityRetrievalEngine, RetrievalResult

# ----------------------------------------------------------------------------
# 100 Independent Evaluation Queries & Pre-Declared Ground Truth
# ----------------------------------------------------------------------------

EVAL_DATASET: List[Dict[str, Any]] = [
    # =========================================================================
    # Category 1: Direct Task Requests (25 Queries)
    # =========================================================================
    {
        "id": "D01",
        "category": "Direct Task",
        "query": "Extract text and structured tables from a local PDF document",
        "expected": ["urn:lcs:tool:mcp.doc-tools:read-pdf-document"],
        "expect_abstain": False
    },
    {
        "id": "D02",
        "category": "Direct Task",
        "query": "Convert a markdown file into standardized PDF format",
        "expected": ["urn:lcs:tool:mcp.doc-tools:convert-document-format"],
        "expect_abstain": False
    },
    {
        "id": "D03",
        "category": "Direct Task",
        "query": "Execute a read-only analytical SQL query on a local SQLite database",
        "expected": ["urn:lcs:tool:mcp.doc-tools:query-local-database"],
        "expect_abstain": False
    },
    {
        "id": "D04",
        "category": "Direct Task",
        "query": "Calculate the surface area of a polygon given coordinates",
        "expected": ["urn:lcs:tool:mcp.geo-tools:calculate-polygon-area"],
        "expect_abstain": False
    },
    {
        "id": "D05",
        "category": "Direct Task",
        "query": "Compute great-circle haversine distance between two geographic waypoints",
        "expected": ["urn:lcs:tool:mcp.geo-tools:compute-haversine-distance"],
        "expect_abstain": False
    },
    {
        "id": "D06",
        "category": "Direct Task",
        "query": "Find the bounding box envelope and centroid for a spatial feature",
        "expected": ["urn:lcs:tool:mcp.geo-tools:find-bounding-envelope"],
        "expect_abstain": False
    },
    {
        "id": "D07",
        "category": "Direct Task",
        "query": "Evaluate web HTTP response headers against security compliance standards",
        "expected": ["urn:lcs:tool:mcp.sdk-analytics:inspect-http-header-security"],
        "expect_abstain": False
    },
    {
        "id": "D08",
        "category": "Direct Task",
        "query": "Calculate statistical sample variance across numeric observations",
        "expected": ["urn:lcs:tool:mcp.sdk-analytics:calculate-statistical-variance"],
        "expect_abstain": False
    },
    {
        "id": "D09",
        "category": "Direct Task",
        "query": "Parse and validate semantic versioning strings into component integers",
        "expected": ["urn:lcs:tool:mcp.sdk-analytics:parse-semver-expression"],
        "expect_abstain": False
    },
    {
        "id": "D10",
        "category": "Direct Task",
        "query": "Verify JSON Web Token cryptographic signatures against public keys",
        "expected": ["urn:lcs:tool:mcp.crypto-security:verify-jwt-signature"],
        "expect_abstain": False
    },
    {
        "id": "D11",
        "category": "Direct Task",
        "query": "Generate time-based one-time password from base32 secret seed",
        "expected": ["urn:lcs:tool:mcp.crypto-security:generate-totp-token"],
        "expect_abstain": False
    },
    {
        "id": "D12",
        "category": "Direct Task",
        "query": "Encrypt raw data payload using AES-256 Galois Counter Mode",
        "expected": ["urn:lcs:tool:mcp.crypto-security:encrypt-aes-gcm"],
        "expect_abstain": False
    },
    {
        "id": "D13",
        "category": "Direct Task",
        "query": "Decrypt ciphertext payload using AES-256 in GCM mode",
        "expected": ["urn:lcs:tool:mcp.crypto-security:decrypt-aes-gcm"],
        "expect_abstain": False
    },
    {
        "id": "D14",
        "category": "Direct Task",
        "query": "Compute cryptographic SHA-256 message digest for input data",
        "expected": ["urn:lcs:tool:mcp.crypto-security:hash-sha256-digest"],
        "expect_abstain": False
    },
    {
        "id": "D15",
        "category": "Direct Task",
        "query": "Inspect X.509 TLS certificate chains and expiration dates for a domain",
        "expected": ["urn:lcs:tool:mcp.crypto-security:inspect-tls-certificate"],
        "expect_abstain": False
    },
    {
        "id": "D16",
        "category": "Direct Task",
        "query": "Check password entropy complexity and character strength",
        "expected": ["urn:lcs:tool:mcp.crypto-security:check-password-entropy"],
        "expect_abstain": False
    },
    {
        "id": "D17",
        "category": "Direct Task",
        "query": "Send ICMP echo ping to verify remote host latency",
        "expected": ["urn:lcs:tool:mcp.system-devops:ping-network-host"],
        "expect_abstain": False
    },
    {
        "id": "D18",
        "category": "Direct Task",
        "query": "Query DNS nameservers for domain resource records",
        "expected": ["urn:lcs:tool:mcp.system-devops:query-dns-records"],
        "expect_abstain": False
    },
    {
        "id": "D19",
        "category": "Direct Task",
        "query": "Inspect CPU and memory utilization for a running process ID",
        "expected": ["urn:lcs:tool:mcp.system-devops:inspect-process-metrics"],
        "expect_abstain": False
    },
    {
        "id": "D20",
        "category": "Direct Task",
        "query": "Parse and validate YAML syntax in configuration manifests",
        "expected": ["urn:lcs:tool:mcp.system-devops:validate-yaml-syntax"],
        "expect_abstain": False
    },
    {
        "id": "D21",
        "category": "Direct Task",
        "query": "Calculate recursive disk usage in bytes across directory hierarchy",
        "expected": ["urn:lcs:tool:mcp.system-devops:calculate-disk-usage"],
        "expect_abstain": False
    },
    {
        "id": "D22",
        "category": "Direct Task",
        "query": "Compress a directory into a tar.gz archive file",
        "expected": ["urn:lcs:tool:mcp.system-devops:compress-tar-archive"],
        "expect_abstain": False
    },
    {
        "id": "D23",
        "category": "Direct Task",
        "query": "Read commit metadata and author info for a git revision hash",
        "expected": ["urn:lcs:tool:mcp.git-vcs:inspect-git-commit"],
        "expect_abstain": False
    },
    {
        "id": "D24",
        "category": "Direct Task",
        "query": "List local and remote branches in a git repository",
        "expected": ["urn:lcs:tool:mcp.git-vcs:list-git-branches"],
        "expect_abstain": False
    },
    {
        "id": "D25",
        "category": "Direct Task",
        "query": "Parse CSV tabular file records into structured dictionaries",
        "expected": ["urn:lcs:tool:mcp.data-transform:parse-csv-records"],
        "expect_abstain": False
    },

    # =========================================================================
    # Category 2: Synonyms & Paraphrasing (20 Queries)
    # =========================================================================
    {
        "id": "S01",
        "category": "Synonyms & Paraphrasing",
        "query": "Parse page contents and font metadata out of an acrobat document",
        "expected": ["urn:lcs:tool:mcp.doc-tools:read-pdf-document"],
        "expect_abstain": False
    },
    {
        "id": "S02",
        "category": "Synonyms & Paraphrasing",
        "query": "Transform docx text document into plaintext or web html",
        "expected": ["urn:lcs:tool:mcp.doc-tools:convert-document-format"],
        "expect_abstain": False
    },
    {
        "id": "S03",
        "category": "Synonyms & Paraphrasing",
        "query": "Run a relational SELECT statement on local db tables",
        "expected": ["urn:lcs:tool:mcp.doc-tools:query-local-database"],
        "expect_abstain": False
    },
    {
        "id": "S04",
        "category": "Synonyms & Paraphrasing",
        "query": "Find the great circle arc range between two GPS lat lon points in kilometers",
        "expected": ["urn:lcs:tool:mcp.geo-tools:compute-haversine-distance"],
        "expect_abstain": False
    },
    {
        "id": "S05",
        "category": "Synonyms & Paraphrasing",
        "query": "Measure the square footprint of this multi-point polygonal parcel",
        "expected": ["urn:lcs:tool:mcp.geo-tools:calculate-polygon-area"],
        "expect_abstain": False
    },
    {
        "id": "S06",
        "category": "Synonyms & Paraphrasing",
        "query": "Determine boundary coordinates bounding box for geographical map layer",
        "expected": ["urn:lcs:tool:mcp.geo-tools:find-bounding-envelope"],
        "expect_abstain": False
    },
    {
        "id": "S07",
        "category": "Synonyms & Paraphrasing",
        "query": "Audit website HSTS and CSP transport security compliance",
        "expected": ["urn:lcs:tool:mcp.sdk-analytics:inspect-http-header-security"],
        "expect_abstain": False
    },
    {
        "id": "S08",
        "category": "Synonyms & Paraphrasing",
        "query": "Compute population variance across measured experimental numbers",
        "expected": ["urn:lcs:tool:mcp.sdk-analytics:calculate-statistical-variance"],
        "expect_abstain": False
    },
    {
        "id": "S09",
        "category": "Synonyms & Paraphrasing",
        "query": "Deconstruct release version numbering into major minor and patch levels",
        "expected": ["urn:lcs:tool:mcp.sdk-analytics:parse-semver-expression"],
        "expect_abstain": False
    },
    {
        "id": "S10",
        "category": "Synonyms & Paraphrasing",
        "query": "Check whether an auth bearer JWT token has been tampered with",
        "expected": ["urn:lcs:tool:mcp.crypto-security:verify-jwt-signature"],
        "expect_abstain": False
    },
    {
        "id": "S11",
        "category": "Synonyms & Paraphrasing",
        "query": "Generate a 2FA two-factor authenticator code from our seed key",
        "expected": ["urn:lcs:tool:mcp.crypto-security:generate-totp-token"],
        "expect_abstain": False
    },
    {
        "id": "S12",
        "category": "Synonyms & Paraphrasing",
        "query": "Scramble secret text with a symmetric cipher key and nonce",
        "expected": ["urn:lcs:tool:mcp.crypto-security:encrypt-aes-gcm"],
        "expect_abstain": False
    },
    {
        "id": "S13",
        "category": "Synonyms & Paraphrasing",
        "query": "Recover original plaintext from encrypted ciphertext payload",
        "expected": ["urn:lcs:tool:mcp.crypto-security:decrypt-aes-gcm"],
        "expect_abstain": False
    },
    {
        "id": "S14",
        "category": "Synonyms & Paraphrasing",
        "query": "Generate a SHA256 checksum fingerprint for this payload",
        "expected": ["urn:lcs:tool:mcp.crypto-security:hash-sha256-digest"],
        "expect_abstain": False
    },
    {
        "id": "S15",
        "category": "Synonyms & Paraphrasing",
        "query": "Look at the SSL cert expiration date on our web server",
        "expected": ["urn:lcs:tool:mcp.crypto-security:inspect-tls-certificate"],
        "expect_abstain": False
    },
    {
        "id": "S16",
        "category": "Synonyms & Paraphrasing",
        "query": "Check if a target machine answers ICMP packets across the internet",
        "expected": ["urn:lcs:tool:mcp.system-devops:ping-network-host"],
        "expect_abstain": False
    },
    {
        "id": "S17",
        "category": "Synonyms & Paraphrasing",
        "query": "Look up MX mail server host records for a domain",
        "expected": ["urn:lcs:tool:mcp.system-devops:query-dns-records"],
        "expect_abstain": False
    },
    {
        "id": "S18",
        "category": "Synonyms & Paraphrasing",
        "query": "Monitor recent log stream entries from syslog file",
        "expected": ["urn:lcs:tool:mcp.system-devops:tail-system-log"],
        "expect_abstain": False
    },
    {
        "id": "S19",
        "category": "Synonyms & Paraphrasing",
        "query": "Who committed the latest code changes in this git repo",
        "expected": ["urn:lcs:tool:mcp.git-vcs:inspect-git-commit"],
        "expect_abstain": False
    },
    {
        "id": "S20",
        "category": "Synonyms & Paraphrasing",
        "query": "Sanitize raw html string by stripping unsafe tags",
        "expected": ["urn:lcs:tool:mcp.data-transform:clean-html-markup"],
        "expect_abstain": False
    },

    # =========================================================================
    # Category 3: Lexical Overlap Traps (15 Queries)
    # =========================================================================
    {
        "id": "T01",
        "category": "Lexical Trap",
        "query": "Format this SQL select query according to standard database style guidelines",
        "expected": ["urn:lcs:tool:mcp.data-transform:format-sql-query"],
        "expect_abstain": False
        # Trap: Mentions 'SQL', 'query', 'database', 'format'. Must pick format_sql_query, NOT query_local_database!
    },
    {
        "id": "T02",
        "category": "Lexical Trap",
        "query": "Format raw JSON document string with standard indentation",
        "expected": ["urn:lcs:tool:mcp.system-devops:format-json-document"],
        "expect_abstain": False
        # Trap: Mentions 'format', 'document'. Must pick format_json_document, NOT convert_document_format!
    },
    {
        "id": "T03",
        "category": "Lexical Trap",
        "query": "Format unified git diff output between two branches",
        "expected": ["urn:lcs:tool:mcp.git-vcs:format-git-diff"],
        "expect_abstain": False
        # Trap: Mentions 'format'. Must pick format_git_diff!
    },
    {
        "id": "T04",
        "category": "Lexical Trap",
        "query": "Format binary DER certificate into armored PEM text",
        "expected": ["urn:lcs:tool:mcp.crypto-security:format-certificate-pem"],
        "expect_abstain": False
        # Trap: Mentions 'format', 'certificate'. Must pick format_certificate_pem, NOT convert_document_format!
    },
    {
        "id": "T05",
        "category": "Lexical Trap",
        "query": "Query DNS nameserver for mail exchange MX records",
        "expected": ["urn:lcs:tool:mcp.system-devops:query-dns-records"],
        "expect_abstain": False
        # Trap: Mentions 'query', 'records'. Must pick query_dns_records, NOT query_local_database!
    },
    {
        "id": "T06",
        "category": "Lexical Trap",
        "query": "Inspect the SSL certificate on our website",
        "expected": ["urn:lcs:tool:mcp.crypto-security:inspect-tls-certificate"],
        "expect_abstain": False
        # Trap: Mentions 'inspect', 'website'. Must pick inspect_tls_certificate, NOT inspect_http_header_security!
    },
    {
        "id": "T07",
        "category": "Lexical Trap",
        "query": "Inspect process CPU metrics for running PID",
        "expected": ["urn:lcs:tool:mcp.system-devops:inspect-process-metrics"],
        "expect_abstain": False
        # Trap: Mentions 'inspect', 'metrics'. Must pick inspect_process_metrics!
    },
    {
        "id": "T08",
        "category": "Lexical Trap",
        "query": "Extract blame author info line by line from source code file",
        "expected": ["urn:lcs:tool:mcp.git-vcs:extract-git-blame"],
        "expect_abstain": False
        # Trap: Mentions 'extract', 'file'. Must pick extract_git_blame, NOT read_pdf_document!
    },
    {
        "id": "T09",
        "category": "Lexical Trap",
        "query": "Extract regex pattern capture groups from input text",
        "expected": ["urn:lcs:tool:mcp.data-transform:extract-regex-matches"],
        "expect_abstain": False
        # Trap: Mentions 'extract', 'text'. Must pick extract_regex_matches, NOT read_pdf_document!
    },
    {
        "id": "T10",
        "category": "Lexical Trap",
        "query": "Parse CSV records from a tabular file into dictionaries",
        "expected": ["urn:lcs:tool:mcp.data-transform:parse-csv-records"],
        "expect_abstain": False
        # Trap: Mentions 'tabular file', 'records'. Must pick parse_csv_records!
    },
    {
        "id": "T11",
        "category": "Lexical Trap",
        "query": "Calculate the 95th percentile rank of these numbers",
        "expected": ["urn:lcs:tool:mcp.data-transform:calculate-percentile-rank"],
        "expect_abstain": False
        # Trap: Mentions 'calculate', 'numbers'. Must pick calculate_percentile_rank, NOT variance!
    },
    {
        "id": "T12",
        "category": "Lexical Trap",
        "query": "Calculate disk space consumption for a directory",
        "expected": ["urn:lcs:tool:mcp.system-devops:calculate-disk-usage"],
        "expect_abstain": False
        # Trap: Mentions 'calculate'. Must pick calculate_disk_usage, NOT polygon or variance!
    },
    {
        "id": "T13",
        "category": "Lexical Trap",
        "query": "Verify PGP signature on a git commit tag",
        "expected": ["urn:lcs:tool:mcp.git-vcs:verify-pgp-signature"],
        "expect_abstain": False
        # Trap: Mentions 'verify signature'. Must pick verify_pgp_signature, NOT verify_jwt_signature!
    },
    {
        "id": "T14",
        "category": "Lexical Trap",
        "query": "Convert timestamps between different timezones",
        "expected": ["urn:lcs:tool:mcp.data-transform:convert-timezone"],
        "expect_abstain": False
        # Trap: Mentions 'convert'. Must pick convert_timezone, NOT convert_document_format!
    },
    {
        "id": "T15",
        "category": "Lexical Trap",
        "query": "Convert US dollar amount to euros using exchange currency rates",
        "expected": ["urn:lcs:tool:mcp.data-transform:convert-currency-amount"],
        "expect_abstain": False
        # Trap: Mentions 'convert'. Must pick convert_currency_amount, NOT convert_document_format!
    },

    # =========================================================================
    # Category 4: Multi-Capability Workflows (10 Queries)
    # =========================================================================
    {
        "id": "M01",
        "category": "Multi-Capability",
        "query": "Extract data from a PDF document and run an SQL query on the database table",
        "expected": [
            "urn:lcs:tool:mcp.doc-tools:read-pdf-document",
            "urn:lcs:tool:mcp.doc-tools:query-local-database"
        ],
        "expect_abstain": False
    },
    {
        "id": "M02",
        "category": "Multi-Capability",
        "query": "Calculate polygon surface area and compute haversine distance for spatial coordinates",
        "expected": [
            "urn:lcs:tool:mcp.geo-tools:calculate-polygon-area",
            "urn:lcs:tool:mcp.geo-tools:compute-haversine-distance"
        ],
        "expect_abstain": False
    },
    {
        "id": "M03",
        "category": "Multi-Capability",
        "query": "Convert markdown document to PDF and verify website HTTP security headers",
        "expected": [
            "urn:lcs:tool:mcp.doc-tools:convert-document-format",
            "urn:lcs:tool:mcp.sdk-analytics:inspect-http-header-security"
        ],
        "expect_abstain": False
    },
    {
        "id": "M04",
        "category": "Multi-Capability",
        "query": "Encrypt data payload with AES-256 and calculate its SHA-256 hash digest",
        "expected": [
            "urn:lcs:tool:mcp.crypto-security:encrypt-aes-gcm",
            "urn:lcs:tool:mcp.crypto-security:hash-sha256-digest"
        ],
        "expect_abstain": False
    },
    {
        "id": "M05",
        "category": "Multi-Capability",
        "query": "Clone git repository and inspect the latest commit metadata",
        "expected": [
            "urn:lcs:tool:mcp.git-vcs:clone-git-repository",
            "urn:lcs:tool:mcp.git-vcs:inspect-git-commit"
        ],
        "expect_abstain": False
    },
    {
        "id": "M06",
        "category": "Multi-Capability",
        "query": "Parse CSV records and calculate sample statistical variance across values",
        "expected": [
            "urn:lcs:tool:mcp.data-transform:parse-csv-records",
            "urn:lcs:tool:mcp.sdk-analytics:calculate-statistical-variance"
        ],
        "expect_abstain": False
    },
    {
        "id": "M07",
        "category": "Multi-Capability",
        "query": "Check website TLS certificate and inspect HTTP security headers",
        "expected": [
            "urn:lcs:tool:mcp.crypto-security:inspect-tls-certificate",
            "urn:lcs:tool:mcp.sdk-analytics:inspect-http-header-security"
        ],
        "expect_abstain": False
    },
    {
        "id": "M08",
        "category": "Multi-Capability",
        "query": "Format SQL query and execute analytical query on local SQLite database",
        "expected": [
            "urn:lcs:tool:mcp.data-transform:format-sql-query",
            "urn:lcs:tool:mcp.doc-tools:query-local-database"
        ],
        "expect_abstain": False
    },
    {
        "id": "M09",
        "category": "Multi-Capability",
        "query": "List git branches and parse current working tree status",
        "expected": [
            "urn:lcs:tool:mcp.git-vcs:list-git-branches",
            "urn:lcs:tool:mcp.git-vcs:parse-git-status"
        ],
        "expect_abstain": False
    },
    {
        "id": "M10",
        "category": "Multi-Capability",
        "query": "Ping network host and query DNS nameserver for its IP records",
        "expected": [
            "urn:lcs:tool:mcp.system-devops:ping-network-host",
            "urn:lcs:tool:mcp.system-devops:query-dns-records"
        ],
        "expect_abstain": False
    },

    # =========================================================================
    # Category 5: Ambiguous & Underspecified Requests (10 Queries)
    # =========================================================================
    {
        "id": "A01",
        "category": "Ambiguous Request",
        "query": "Process data",
        "expected": [],
        "expect_abstain": True
    },
    {
        "id": "A02",
        "category": "Ambiguous Request",
        "query": "Inspect system",
        "expected": [],
        "expect_abstain": True
    },
    {
        "id": "A03",
        "category": "Ambiguous Request",
        "query": "Handle records",
        "expected": [],
        "expect_abstain": True
    },
    {
        "id": "A04",
        "category": "Ambiguous Request",
        "query": "Run analysis",
        "expected": [],
        "expect_abstain": True
    },
    {
        "id": "A05",
        "category": "Ambiguous Request",
        "query": "Manage items",
        "expected": [],
        "expect_abstain": True
    },
    {
        "id": "A06",
        "category": "Ambiguous Request",
        "query": "Check file",
        "expected": [],
        "expect_abstain": True
    },
    {
        "id": "A07",
        "category": "Ambiguous Request",
        "query": "Verify data",
        "expected": [],
        "expect_abstain": True
    },
    {
        "id": "A08",
        "category": "Ambiguous Request",
        "query": "Execute check",
        "expected": [],
        "expect_abstain": True
    },
    {
        "id": "A09",
        "category": "Ambiguous Request",
        "query": "Format payload",
        "expected": [],
        "expect_abstain": True
    },
    {
        "id": "A10",
        "category": "Ambiguous Request",
        "query": "Analyze information",
        "expected": [],
        "expect_abstain": True
    },

    # =========================================================================
    # Category 6: Out-of-Domain Requests (Must Abstain) (20 Queries)
    # =========================================================================
    {
        "id": "O01",
        "category": "Out-of-Domain",
        "query": "Send an email message with attachment via SMTP server",
        "expected": [],
        "expect_abstain": True
    },
    {
        "id": "O02",
        "category": "Out-of-Domain",
        "query": "Generate high-resolution photorealistic images of a mountain using AI",
        "expected": [],
        "expect_abstain": True
    },
    {
        "id": "O03",
        "category": "Out-of-Domain",
        "query": "Deploy a Docker container to a remote Kubernetes cluster",
        "expected": [],
        "expect_abstain": True
    },
    {
        "id": "O04",
        "category": "Out-of-Domain",
        "query": "Transcribe voice audio recording from MP3 format into English text",
        "expected": [],
        "expect_abstain": True
    },
    {
        "id": "O05",
        "category": "Out-of-Domain",
        "query": "Transpile TypeScript source code into WebAssembly binary",
        "expected": [],
        "expect_abstain": True
    },
    {
        "id": "O06",
        "category": "Out-of-Domain",
        "query": "Mine cryptocurrency blocks using GPU proof of work",
        "expected": [],
        "expect_abstain": True
    },
    {
        "id": "O07",
        "category": "Out-of-Domain",
        "query": "Synthesize realistic human speech from text using neural voice model",
        "expected": [],
        "expect_abstain": True
    },
    {
        "id": "O08",
        "category": "Out-of-Domain",
        "query": "Render 3D animated scene using ray tracing shaders",
        "expected": [],
        "expect_abstain": True
    },
    {
        "id": "O09",
        "category": "Out-of-Domain",
        "query": "Perform optical character recognition OCR on scanned receipt image",
        "expected": [],
        "expect_abstain": True
    },
    {
        "id": "O10",
        "category": "Out-of-Domain",
        "query": "Train a convolutional neural network on CIFAR-10 image dataset",
        "expected": [],
        "expect_abstain": True
    },
    {
        "id": "O11",
        "category": "Out-of-Domain",
        "query": "Book a commercial airline flight from London to Tokyo",
        "expected": [],
        "expect_abstain": True
    },
    {
        "id": "O12",
        "category": "Out-of-Domain",
        "query": "Translate conversational Japanese audio into Spanish subtitles",
        "expected": [],
        "expect_abstain": True
    },
    {
        "id": "O13",
        "category": "Out-of-Domain",
        "query": "Transcode MP4 video file into WebM with VP9 codec compression",
        "expected": [],
        "expect_abstain": True
    },
    {
        "id": "O14",
        "category": "Out-of-Domain",
        "query": "Process credit card payment transaction through Stripe gateway",
        "expected": [],
        "expect_abstain": True
    },
    {
        "id": "O15",
        "category": "Out-of-Domain",
        "query": "Simulate aerodynamic drag coefficient for Formula 1 car wing",
        "expected": [],
        "expect_abstain": True
    },
    {
        "id": "O16",
        "category": "Out-of-Domain",
        "query": "Turn on living room smart light bulbs and adjust color temperature",
        "expected": [],
        "expect_abstain": True
    },
    {
        "id": "O17",
        "category": "Out-of-Domain",
        "query": "Calculate compound interest for 30-year fixed mortgage loan",
        "expected": [],
        "expect_abstain": True
    },
    {
        "id": "O18",
        "category": "Out-of-Domain",
        "query": "Scrape product prices from Amazon ecommerce catalog",
        "expected": [],
        "expect_abstain": True
    },
    {
        "id": "O19",
        "category": "Out-of-Domain",
        "query": "Generate QR code barcode for Wi-Fi network credentials",
        "expected": [],
        "expect_abstain": True
    },
    {
        "id": "O20",
        "category": "Out-of-Domain",
        "query": "Generate interactive Gantt chart schedule for project sprint",
        "expected": [],
        "expect_abstain": True
    }
]


def run_evaluation():
    print("=" * 78)
    print(" LCS RETRIEVAL V1 — INDEPENDENT 100-QUERY GENERALIZATION EVALUATION")
    print("=" * 78)

    with tempfile.TemporaryDirectory() as td:
        cfg = LCSConfig.resolve(root_override=td)
        ctx = LCSContext(cfg)
        policy = InterfaceTrustPolicy(
            policy_name="generalization-audit-policy",
            allowed_attester_ids={"urn:lcs:attester:security:local-authority"},
            min_interface_version=1,
            require_attestation=True,
            require_all_capabilities_verified=True
        )

        # Ingest all 7 independent servers
        servers = [
            ("doc-tools", "mcp_test_server_fixture.py"),
            ("geo-tools", "integration_tests/independent_mcp_server.py"),
            ("sdk-analytics", "integration_tests/mcp_sdk_server.py"),
            ("crypto-security", "evaluation_fixtures/crypto_security_server.py"),
            ("system-devops", "evaluation_fixtures/system_devops_server.py"),
            ("git-vcs", "evaluation_fixtures/git_vcs_server.py"),
            ("data-transform", "evaluation_fixtures/data_transform_server.py")
        ]

        for s_name, s_rel in servers:
            s_path = os.path.join(PROJ_ROOT, s_rel)
            ctx.discovery_pipeline.discover_and_register_mcp_server(
                command=[sys.executable, s_path],
                server_name=s_name,
                trust_policy=policy
            )

        cur = ctx.conn.cursor()
        cur.execute("SELECT count(*) FROM capability_declarations;")
        corpus_size = cur.fetchone()[0]
        print(f"Registered Corpus Size: {corpus_size} capabilities across {len(servers)} servers.\n")

        # Metrics trackers
        p1_hits = 0
        p3_hits = 0
        recall_hits = 0
        total_targets_count = 0
        reciprocal_ranks = []
        false_positives = 0
        correct_abstentions = 0
        total_abstention_queries = 0

        # Category metrics: cat -> {"total": int, "p1": int, "correct_abstain": int, "targets": int, "rec_hits": int}
        cat_stats: Dict[str, Dict[str, Any]] = {}
        for item in EVAL_DATASET:
            c_name = item["category"]
            if c_name not in cat_stats:
                cat_stats[c_name] = {
                    "total": 0, "p1": 0, "recall_hits": 0, "targets": 0,
                    "correct_abstain": 0, "abstain_expected": 0, "reciprocal_ranks": []
                }

        failures: List[Dict[str, Any]] = []

        for item in EVAL_DATASET:
            qid = item["id"]
            cat = item["category"]
            q = item["query"]
            exp = item["expected"]
            expect_abstain = item["expect_abstain"]

            cat_stats[cat]["total"] += 1

            # Execute frozen retrieval engine
            res = ctx.retrieval_engine.retrieve(q, limit=5, min_score_threshold=0.25)
            candidates = res.candidates
            candidate_urns = [c.capability_urn for c in candidates]

            is_correct = False
            failure_reason = None

            if expect_abstain:
                total_abstention_queries += 1
                cat_stats[cat]["abstain_expected"] += 1
                if res.abstained:
                    correct_abstentions += 1
                    cat_stats[cat]["correct_abstain"] += 1
                    is_correct = True
                    status_str = f"ABSTAINED ({res.abstention_code})"
                else:
                    false_positives += 1
                    status_str = f"FALSE POSITIVE -> {candidate_urns[0]} ({candidates[0].relevance_score:.3f})"
                    failure_reason = (
                        f"Expected engine to abstain on out-of-domain or ambiguous query, "
                        f"but candidate '{candidate_urns[0]}' scored {candidates[0].relevance_score:.3f} >= 0.25."
                    )
            else:
                total_targets_count += len(exp)
                cat_stats[cat]["targets"] += len(exp)

                # Precision@1
                if candidate_urns and candidate_urns[0] in exp:
                    p1_hits += 1
                    cat_stats[cat]["p1"] += 1

                # Top-3 matches
                top3_urns = candidate_urns[:3]
                matched_in_top3 = [t for t in exp if t in top3_urns]
                p3_hits += len(matched_in_top3) / min(3, max(1, len(top3_urns)))
                recall_hits += len(matched_in_top3)
                cat_stats[cat]["recall_hits"] += len(matched_in_top3)

                # MRR
                rr = 0.0
                for rank, c_urn in enumerate(candidate_urns, start=1):
                    if c_urn in exp:
                        rr = 1.0 / rank
                        break
                reciprocal_ranks.append(rr)
                cat_stats[cat]["reciprocal_ranks"].append(rr)

                if candidate_urns and candidate_urns[0] in exp:
                    is_correct = True
                    status_str = f"RANK 1 HIT: {candidate_urns[0]} (score={candidates[0].relevance_score:.3f})"
                elif candidate_urns and any(t in candidate_urns for t in exp):
                    status_str = f"TOP-3 HIT (RR={rr:.2f}): {candidate_urns}"
                    failure_reason = f"Target was retrieved in rank {int(1.0/rr)}, but not rank 1. Top was '{candidate_urns[0]}'."
                else:
                    status_str = f"MISSED: Expected {exp}, got {candidate_urns or '(Abstained)'}"
                    if res.abstained:
                        failure_reason = f"Engine abstained ({res.abstention_code}) but expected {exp}."
                    else:
                        failure_reason = f"Ranked candidates did not include expected targets {exp}."

            print(f"[{qid}] [{cat:22}] \"{q[:42]}...\" -> {status_str}")

            if not is_correct or failure_reason:
                failures.append({
                    "id": qid,
                    "category": cat,
                    "query": q,
                    "expected": exp,
                    "expect_abstain": expect_abstain,
                    "abstained": res.abstained,
                    "abstention_code": res.abstention_code,
                    "returned_candidates": [
                        {"urn": c.capability_urn, "score": round(c.relevance_score, 4), "name": c.display_name}
                        for c in candidates
                    ],
                    "failure_analysis": failure_reason
                })

        # Summary calculations
        n_matched = len(EVAL_DATASET) - total_abstention_queries
        p1 = (p1_hits / n_matched) if n_matched > 0 else 0.0
        p3 = (p3_hits / n_matched) if n_matched > 0 else 0.0
        recall3 = (recall_hits / total_targets_count) if total_targets_count > 0 else 0.0
        mrr = (sum(reciprocal_ranks) / len(reciprocal_ranks)) if reciprocal_ranks else 0.0
        abstain_rate = (correct_abstentions / total_abstention_queries) if total_abstention_queries > 0 else 0.0
        fp_rate = (false_positives / total_abstention_queries) if total_abstention_queries > 0 else 0.0

        print("\n" + "=" * 78)
        print(" 100-QUERY GENERALIZATION BENCHMARK SUMMARY")
        print("=" * 78)
        print(f"  Total Queries Evaluated:       {len(EVAL_DATASET)}")
        print(f"  Target Match Tasks:            {n_matched}")
        print(f"  Expected Abstention Tasks:     {total_abstention_queries}")
        print("-" * 78)
        print(f"  Precision@1:                   {p1 * 100:.1f}% ({p1_hits}/{n_matched})")
        print(f"  Precision@3:                   {p3 * 100:.1f}%")
        print(f"  Recall@3:                      {recall3 * 100:.1f}% ({recall_hits}/{total_targets_count})")
        print(f"  Mean Reciprocal Rank (MRR):    {mrr:.4f}")
        print(f"  Correct Abstention Rate:       {abstain_rate * 100:.1f}% ({correct_abstentions}/{total_abstention_queries})")
        print(f"  False-Positive Count / Rate:   {false_positives} ({fp_rate * 100:.1f}%)")
        print(f"  Total Audited Failures:        {len(failures)}")
        print("=" * 78)

        print("\n" + "=" * 78)
        print(" CATEGORY-BY-CATEGORY BREAKDOWN")
        print("=" * 78)
        print(f"{'Category':25} | {'Total':5} | {'P@1':6} | {'Recall@3':8} | {'Abstain %':9} | {'MRR':6}")
        print("-" * 78)
        for c_name, c_data in cat_stats.items():
            c_tot = c_data["total"]
            c_targ = c_data["targets"]
            c_p1_str = f"{(c_data['p1'] / c_tot)*100:.1f}%" if c_targ > 0 else "N/A"
            c_rec_str = f"{(c_data['recall_hits'] / c_targ)*100:.1f}%" if c_targ > 0 else "N/A"
            c_abs_str = f"{(c_data['correct_abstain'] / c_data['abstain_expected'])*100:.1f}%" if c_data['abstain_expected'] > 0 else "N/A"
            c_mrr = sum(c_data["reciprocal_ranks"]) / len(c_data["reciprocal_ranks"]) if c_data["reciprocal_ranks"] else 0.0
            c_mrr_str = f"{c_mrr:.4f}" if c_targ > 0 else "N/A"
            print(f"{c_name:25} | {c_tot:5} | {c_p1_str:6} | {c_rec_str:8} | {c_abs_str:9} | {c_mrr_str:6}")
        print("=" * 78)

        return {
            "corpus_size": corpus_size,
            "total_queries": len(EVAL_DATASET),
            "p1": p1,
            "p3": p3,
            "recall3": recall3,
            "mrr": mrr,
            "abstain_rate": abstain_rate,
            "fp_rate": fp_rate,
            "cat_stats": cat_stats,
            "failures": failures
        }


if __name__ == "__main__":
    run_evaluation()

