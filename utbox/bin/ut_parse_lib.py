import json
import re
import sys
from io import StringIO
from ipaddress import ip_address
from pathlib import Path
from urllib.parse import urlparse

if sys.version_info[:2] == (3, 7):
    lib_path = Path(__file__).resolve().parents[1] / "lib37"
    sys.path.append(str(lib_path))
else:
    assert sys.version_info[:2] == (3, 9)
    lib_path = Path(__file__).resolve().parents[1] / "lib"
    sys.path.append(str(lib_path))

import publicsuffixlist

import ut_log_lib

preg_rfc1808 = re.compile("^[^/?&;=#]{1,200}://")
preg_ipv4 = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
preg_ipv6 = re.compile(r"^\[[0-9A-Fa-f:]+]$")

urllib_schemes = {
    "ftp": "21",
    "http": "80",
    "https": "443",
    "imap": "143",
    "sftp": "22",
    "sip": "5060",
    "ssh": "22",
}

#############
# FUNCTIONS #
#############
logger = ut_log_lib.setup_logger()


def get_public_suffix_list(tld_list="iana"):
    valid_lists = {"iana", "icann", "mozilla", "custom"}
    if tld_list not in valid_lists:
        logger.error(f"Invalid TLD list {tld_list}, loading IANA list.")
        tld_list = "iana"

    from publicsuffixlist import PublicSuffixList
    default_config = Path(__file__).resolve().parents[1] / "default"
    local_config = Path(__file__).resolve().parents[1] / "local"

    mozilla_list = local_config / "public_suffix_list.dat"
    if not mozilla_list.is_file():
        mozilla_list = default_config / "public_suffix_list.dat"

    iana_list = local_config / "tlds-alpha-by-domain.txt"
    if not iana_list.is_file():
        iana_list = default_config / "tlds-alpha-by-domain.txt"

    custom_list = local_config / "public_suffix_list_custom.dat"

    # Use IANA list
    if tld_list == "iana":
        only_icann = True
        f = StringIO()
        # Put ICANN comments so IANA TLDS can be loaded by PublicSuffixList
        f.write("// ===BEGIN ICANN DOMAINS===\n")
        with open(iana_list) as f_iana:
            for line in f_iana:
                if not line.startswith("#"):
                    f.write(line)
        f.write(iana_list.read_text())
        f.write("\n// ===END ICANN DOMAINS===\n")
        f.seek(0)
        logger.info("loaded IANA domains")
        return PublicSuffixList(source=f, only_icann=only_icann)

    # Use base PublicSuffixList
    if tld_list in ("mozilla", "icann"):
        tld_list_path = mozilla_list
        only_icann = True if tld_list == "icann" else False

    # Use custom list
    else:
        tld_list_path = custom_list
        only_icann = False

    with open(tld_list_path) as f:
        psl = PublicSuffixList(source=f, only_icann=only_icann)

    return psl


def extended_split(
    scheme: str,
    netloc: str,
    suffix_list: publicsuffixlist.PublicSuffixList,
) -> dict:
    """
    Extensive split of the domain name with Mozilla Suffix List.
    """

    ret = {
        "ut_domain": "None",
        "ut_tld": "None",
        "ut_domain_without_tld": "None",
        "ut_subdomain": "None",
        "ut_subdomain_parts": "None",
        "ut_subdomain_count": "0",
        "ut_port": "None",
    }

    # fix for base64
    host_without_port = netloc.lower()

    # extract the port from the netloc and remove it
    # IPv6 address
    if ":" in netloc and netloc[:-1] != "]":
        n, p = netloc.rsplit(":", 1)
        ret["ut_port"] = p
        host_without_port = n

    # If a port isn't in the netloc, add ports for common schemes
    if ret["ut_port"] == "None" and scheme in urllib_schemes:
        ret["ut_port"] = urllib_schemes[scheme]

    # find the TLD
    tld = suffix_list.publicsuffix(host_without_port)

    if tld is None:

        # if this is an IP, we just copy it
        if preg_ipv4.search(host_without_port) or preg_ipv6.search(host_without_port):
            try:
                ip = ip_address(host_without_port.strip("[]"))
                ret["ut_domain"] = ret["ut_domain_without_tld"] = ip.compressed
            except ValueError:
                ret["ut_domain"] = ret["ut_domain_without_tld"] = host_without_port

        return ret

    ret["ut_tld"] = tld

    all_parts = suffix_list.privateparts(host_without_port)
    if all_parts is None:
        return ret

    subdomain_parts, domain = list(all_parts[:-1]), all_parts[-1]
    domain_without_tld = domain.split(".", 1)[0]

    ret["ut_domain"] = domain
    ret["ut_domain_without_tld"] = domain_without_tld

    number_of_subdomains = len(subdomain_parts)
    if number_of_subdomains:
        ret["ut_subdomain_count"] = f"{number_of_subdomains}"
        ret["ut_subdomain"] = ".".join(subdomain_parts)

        sp = {}
        for i, p in zip(range(number_of_subdomains, 0, -1), subdomain_parts):
            sp[f"ut_subdomain_level_{i}"] = p

        ret["ut_subdomain_parts"] = json.dumps(sp)

    return ret


def parse_simple(url):
    # Following the syntax specifications in RFC 1808, urlparse recognizes
    # a netloc only if it is properly introduced by '//'.
    if not preg_rfc1808.search(url):
        url = f"//{url}"

    try:
        url_vals = urlparse(url)
    except Exception as e:
        raise e

    keys = ["ut_scheme", "ut_netloc", "ut_path", "ut_params", "ut_query", "ut_fragment"]
    return {k: v if v else "None" for k, v in zip(keys, url_vals)}


def parse_extended(url, suffix_list: publicsuffixlist.PublicSuffixList):
    res = parse_simple(url)
    r = extended_split(res["ut_scheme"], res["ut_netloc"], suffix_list)
    res.update(r)

    return res
