#!/usr/bin/env python3
"""
LCS Evaluation Fixture — Cryptographic & Security Tools MCP Server
==================================================================
Standard JSON-RPC 2.0 MCP server running over stdio for retrieval generalization testing.
Exposes 8 cryptographic and security tools with varied schemas.
Strictly disallows tools/call execution.
"""

import sys
import json
from typing import Dict, Any, List

TOOLS: List[Dict[str, Any]] = [
    {
        "name": "verify_jwt_signature",
        "description": "Verifies JSON Web Token cryptographic signatures against public keys or shared secrets.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "token": {"type": "string", "description": "Encoded JWT string to verify"},
                "public_key": {"type": "string", "description": "PEM-encoded public key or HMAC secret"},
                "algorithm": {"type": "string", "enum": ["RS256", "ES256", "HS256"], "default": "RS256"}
            },
            "required": ["token", "public_key"]
        }
    },
    {
        "name": "generate_totp_token",
        "description": "Generates time-based one-time passwords from shared base32 secret seeds.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "secret": {"type": "string", "description": "Base32-encoded TOTP secret key"},
                "interval": {"type": "integer", "default": 30},
                "digits": {"type": "integer", "default": 6}
            },
            "required": ["secret"]
        }
    },
    {
        "name": "encrypt_aes_gcm",
        "description": "Encrypts raw data payloads using AES-256 in Galois/Counter Mode.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "plaintext": {"type": "string", "description": "Text payload to encrypt"},
                "key_hex": {"type": "string", "description": "Hex-encoded 256-bit symmetric encryption key"},
                "nonce_hex": {"type": "string", "description": "Hex-encoded 96-bit initialization nonce"}
            },
            "required": ["plaintext", "key_hex"]
        }
    },
    {
        "name": "decrypt_aes_gcm",
        "description": "Decrypts ciphertext payloads using AES-256 in Galois/Counter Mode.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ciphertext": {"type": "string", "description": "Hex-encoded ciphertext payload"},
                "key_hex": {"type": "string", "description": "Hex-encoded 256-bit symmetric key"},
                "nonce_hex": {"type": "string", "description": "Hex-encoded initialization nonce"}
            },
            "required": ["ciphertext", "key_hex", "nonce_hex"]
        }
    },
    {
        "name": "hash_sha256_digest",
        "description": "Computes cryptographic SHA-256 message digests for arbitrary data streams.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "data": {"type": "string", "description": "Payload string to hash"}
            },
            "required": ["data"]
        }
    },
    {
        "name": "inspect_tls_certificate",
        "description": "Inspects X.509 TLS/SSL certificate chains, expiry dates, and subject alternative names.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "hostname": {"type": "string", "description": "Remote domain or host to connect to"},
                "port": {"type": "integer", "default": 443}
            },
            "required": ["hostname"]
        }
    },
    {
        "name": "check_password_entropy",
        "description": "Evaluates password string complexity, character entropy, and breach vulnerability.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "password": {"type": "string", "description": "Password string to evaluate for strength"}
            },
            "required": ["password"]
        }
    },
    {
        "name": "format_certificate_pem",
        "description": "Formats DER binary cryptographic certificates into ASCII armored PEM blocks.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "der_hex": {"type": "string", "description": "Hex-encoded DER certificate bytes"},
                "cert_type": {"type": "string", "enum": ["CERTIFICATE", "PUBLIC KEY", "PRIVATE KEY"], "default": "CERTIFICATE"}
            },
            "required": ["der_hex"]
        }
    }
]


def send_response(resp: Dict[str, Any]) -> None:
    line = json.dumps(resp) + "\n"
    sys.stdout.write(line)
    sys.stdout.flush()


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except Exception:
            continue

        req_id = req.get("id")
        method = req.get("method")
        params = req.get("params", {})

        if req_id is None:
            continue

        if method == "initialize":
            send_response({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": "crypto-security-tools", "version": "1.0.0"}
                }
            })
        elif method == "tools/list":
            send_response({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"tools": TOOLS}
            })
        elif method == "tools/call":
            send_response({
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32601, "message": "Tool execution prohibited by LCS security policy"}
            })
        else:
            send_response({
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32601, "message": f"Method {method} not supported"}
            })


if __name__ == "__main__":
    main()

