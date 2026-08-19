"""
lib/favicon_hash.py — MurmurHash3 favicon fingerprinting (plan Phase 42)
Used for Shodan-style passive asset correlation.
"""
from __future__ import annotations

import base64
import hashlib
import struct
import sys
import urllib.request
from pathlib import Path


def _mmh3_32(data: bytes, seed: int = 0) -> int:
    """Pure-Python MurmurHash3 32-bit (matches Shodan's implementation)."""
    length = len(data)
    nblocks = length // 4
    h1 = seed & 0xFFFFFFFF
    c1, c2 = 0xcc9e2d51, 0x1b873593

    for block_start in range(0, nblocks * 4, 4):
        k1 = struct.unpack_from("<I", data, block_start)[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xe6546b64) & 0xFFFFFFFF

    tail = data[nblocks * 4:]
    k1 = 0
    tail_size = length & 3
    if tail_size >= 3:
        k1 ^= tail[2] << 16
    if tail_size >= 2:
        k1 ^= tail[1] << 8
    if tail_size >= 1:
        k1 ^= tail[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1

    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85ebca6b) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1 = (h1 * 0xc2b2ae35) & 0xFFFFFFFF
    h1 ^= h1 >> 16

    # Return as signed 32-bit int (Shodan convention)
    return struct.unpack("i", struct.pack("I", h1))[0]


def hash_favicon_bytes(data: bytes) -> int:
    """Compute Shodan-style MurmurHash3 of raw favicon bytes."""
    encoded = base64.encodebytes(data)
    return _mmh3_32(encoded)


def hash_favicon_file(path: str | Path) -> int:
    """Compute favicon hash from a local file."""
    return hash_favicon_bytes(Path(path).read_bytes())


def hash_favicon_url(url: str, timeout: int = 10) -> dict:
    """
    Fetch a favicon from a URL and compute its hash.
    Returns {"url": ..., "hash": ..., "shodan_query": ...} or {"error": ...}
    """
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = resp.read()
        h = hash_favicon_bytes(data)
        return {
            "url": url,
            "hash": h,
            "shodan_query": f"http.favicon.hash:{h}",
            "size_bytes": len(data),
        }
    except Exception as e:
        return {"url": url, "error": str(e), "hash": None}


def discover_favicon_url(base_url: str) -> str:
    """Return the conventional favicon URL for a base URL."""
    base_url = base_url.rstrip("/")
    return f"{base_url}/favicon.ico"
