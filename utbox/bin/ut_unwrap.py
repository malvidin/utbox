#!/usr/bin/env python3

"""
URL Defense Unwrapper Module

This module provides functionality to decode URLs that have been wrapped by various
URL defense mechanisms like Microsoft SafeLinks and Proofpoint UrlDefense.

Supported URL defense mechanisms:
- Microsoft SafeLinks
- Proofpoint UrlDefense (versions v1, v2, v3)

Usage:
    from ut_unwrap import unwrap

    original_url = unwrap(wrapped_url)

The module provides the following main functions:
- unwrap(): Main entry point that attempts to unwrap URLs using all supported mechanisms
- unwrap_safelinks(): Specifically unwraps Microsoft SafeLinks URLs
- unwrap_urldefense(): Specifically unwraps Proofpoint UrlDefense URLs
"""
import csv
import re
import string
import sys
from base64 import b64decode
from typing import Dict
from urllib.parse import parse_qs, unquote, urlparse

import ut_log_lib

# setup logging
logger = ut_log_lib.setup_logger()

# Proofpoint UrlDefense v3 special character encoding
PP_B64 = string.ascii_uppercase + string.ascii_lowercase + string.digits + "-_"
PP_CHAR_LEN = {"*": 1}
PP_CHAR_LEN.update({f"**{x}": y + 2 for x, y in zip(PP_B64, range(len(PP_B64)))})


def unwrap_safelinks(url: str) -> str:
    """Decode Microsoft SafeLinks encoded URLs."""

    url_parsed = urlparse(url)
    if not url_parsed.netloc:
        return ""

    if ".safelinks.protection." in url_parsed.netloc:
        uri_query = parse_qs(url_parsed.query)
        if "url" in uri_query:
            wrapped_url = uri_query.get("url")
            if wrapped_url:
                return wrapped_url[0]

    return ""


def unwrap_fireeye(url: str) -> str:
    """Decode FireEye encoded URLs."""

    url_parsed = urlparse(url)
    if not url_parsed.netloc:
        return ""

    if "protect2.fireeye." in url_parsed.netloc:
        uri_query = parse_qs(url_parsed.query)
        if "u" in uri_query:
            wrapped_url = uri_query.get("u")
            if wrapped_url:
                return wrapped_url[0]

    return ""


def unwrap_cisco(url: str) -> str:
    """Decode Cisco encoded URLs."""

    url_parsed = urlparse(url)
    if not url_parsed.netloc:
        return ""

    if "secure-web." in url_parsed.netloc:
        url_path = re.sub(r"^/[^/]*/", "", url_parsed.path)
        return unquote(url_path)

    return ""


def unwrap_barracuda(url: str) -> str:
    """Decode Barracuda encoded URLs."""

    url_parsed = urlparse(url)
    if not url_parsed.netloc:
        return ""

    if "linkprotect." in url_parsed.netloc:
        uri_query = parse_qs(url_parsed.query)
        if "a" in uri_query:
            wrapped_url = uri_query.get("a")
            if wrapped_url:
                return wrapped_url[0]

    return ""


def unwrap_urldefense_v3(url_path: str) -> str:
    """Decode Proofpoint UrlDefense v3 encoded URLs."""

    logger.debug(f"Unwrapping UrlDefense v3 path {url_path}")

    url_match = re.search(
        r"/v3/__(?P<url>.*)__;(?P<encoded_bytes>[^!]+)?",
        url_path,
        re.IGNORECASE,
    )
    if not url_match:
        return ""

    wrapped_url = url_match["url"]
    encoded_bytes = url_match["encoded_bytes"]

    # Fix URL with a single slash before authority
    wrapped_url = re.sub(r"^([0-9A-Za-z.-]{0,10}:/)(?!/)", r"\1/", wrapped_url)

    def v3_sub(m: re.Match) -> str:
        nonlocal decoded_bytes
        matched_str = m.group(0)
        char_len = PP_CHAR_LEN.get(matched_str)
        val, decoded_bytes = decoded_bytes[:char_len], decoded_bytes[char_len:]
        return val

    if encoded_bytes is not None and len(encoded_bytes) > 0:
        # Pad with '=' to ensure correct decoding
        if len(encoded_bytes) % 4 == 1:
            encoded_bytes += "A"
        b64_padding = "=" * ((4 - len(encoded_bytes) % 4) % 4)
        decoded_bytes = b64decode(encoded_bytes + b64_padding).decode("utf-8")
        return re.sub(r"[*](?:[*][A-Za-z0-9_-])?", repl=v3_sub, string=wrapped_url)

    return wrapped_url


def unwrap_urldefense(url: str) -> str:
    """
    Decode Proofpoint UrlDefense encoded URLs
    https://help.proofpoint.com/Threat_Insight_Dashboard/Concepts/How_do_I_decode_a_rewritten_URL%3F
    """

    url_parsed = urlparse(url)
    if not url_parsed.netloc:
        return ""

    logger.debug(f"Unwrapping UrlDefense netloc {url_parsed}")

    uri_path = url_parsed.path
    if url_parsed.netloc in [
        "urldefense.proofpoint.com",
        "urldefense.com",
    ] and uri_path[:4] in ["/v1/", "/v2/", "/v3/"]:
        ud_version = uri_path[1:3]
        logger.debug(f"Unwrapping UrlDefense version {ud_version}")
        # Handle UrlDefense versions
        if ud_version in ("v1", "v2"):
            qsl = parse_qs(url_parsed.query)
            if "u" in qsl:
                return qsl["u"][0]
        if ud_version == "v3":
            url_path = f"{url_parsed.path};{url_parsed.params}"
            return unwrap_urldefense_v3(url_path)

    return ""


def unwrap(url: str) -> Dict[str, str]:
    """
    Recursively unwrap URLs using all supported URL defense mechanisms.
    Some URLs are wrapped multiple times during email communication after multiple replies.
    If it is wrapped more than 50 times, it will return the last unwrapped URL.

    :param url: The input URL that may be wrapped by a URL defense mechanism.
    :type url: str
    :return: The unwrapped original URL if identified; otherwise, a blank string.
    :rtype: str
    """

    if "&amp;" in url:
        url.replace("&amp;", "&")

    logger.debug(f"Unwrapping {url}")

    orig_url = url
    unwrapped_url = ""

    for i in range(10):
        # Attempt to unwrap URL using all supported URL wrapping mechanisms
        for unwrap_func in (
            unwrap_barracuda,
            unwrap_cisco,
            unwrap_fireeye,
            unwrap_safelinks,
            unwrap_urldefense,
        ):
            logger.debug(f"Unwrapping with {unwrap_func.__name__}")
            try:
                unwrapped_url = unwrap_func(url)
                if unwrapped_url:
                    # Set url for the next outer loop and break out of the inner loop
                    url = unwrapped_url
                    break
            except Exception as e:
                logger.error(f"Unexpected decoding error: {e}")
                continue
        # Could not unwrap URL, return empty string
        if url == orig_url:
            return {"ut_unwrap": "None"}
        # Could not unwrap URL again, return previously unwrapped URL
        if unwrapped_url == "":
            return {"ut_unwrap": url}

    return {"ut_unwrap": unwrapped_url}


def main():
    header = ["url", "ut_unwrap"]

    csv_in = csv.DictReader(sys.stdin)  # use the first line as header
    csv_out = csv.DictWriter(sys.stdout, header)
    csv_out.writeheader()  # write header

    for row in csv_in:
        url = row["url"].strip()

        try:
            res = unwrap(url)
            row.update(res)
        except Exception as e:
            logger.error("Got error %s on with url %s" % (str(e), url))

        # return row to Splunk
        csv_out.writerow(row)


if __name__ == "__main__":
    main()
