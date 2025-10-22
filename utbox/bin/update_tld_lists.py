import logging
import re
import sys
import xml.dom.minidom
import xml.sax.saxutils
from pathlib import Path

from generate_psl_lookup import generate_lookup

if sys.version_info[:2] == (3, 7):
    lib_path = Path(__file__).resolve().parents[1] / "lib37"
    sys.path.append(str(lib_path))
else:
    assert sys.version_info[:2] == (3, 9)
    lib_path = Path(__file__).resolve().parents[1] / "lib"
    sys.path.append(str(lib_path))

import requests

import ut_log_lib

logger = ut_log_lib.setup_logger()

stdout_handler = logging.StreamHandler(sys.stdout)
logger.addHandler(stdout_handler)


# Empty introspection routine
def do_scheme():
    pass


# Empty validation routine
def validate_arguments():
    pass


def download_psl(psl_url=None) -> str:
    # Download the latest public suffix list
    psl_url = psl_url or "https://publicsuffix.org/list/public_suffix_list.dat"
    resp = requests.get(psl_url)
    resp.raise_for_status()
    public_suffix_list = resp.text

    # Verify the downloaded list
    assert (
        "===BEGIN ICANN DOMAINS===" in public_suffix_list[:2000]
    ), "Downloaded list does not appear to be a valid Mozilla PSL file."

    logger.info("Successfully downloaded Mozilla Public Suffix List.")

    return public_suffix_list


def download_iana(iana_url=None) -> str:
    # Download the latest IANA list
    iana_url = iana_url or "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"
    resp = requests.get(iana_url)
    resp.raise_for_status()
    iana_list = resp.text

    # Verify the downloaded list
    assert re.match(
        r"# Version \d+, Last Updated", iana_list[:2000]
    ), "Downloaded list does not appear to be a valid IANA TLD list."

    logger.info("Successfully downloaded IANA TLD list.")

    return iana_list


def update_custom_list(custom_list: Path, public_suffix_list: str):
    """Updates custom Public Suffix List content and saves it to local/public_suffix_list_custom.dat."""
    public_suffix_list_lines = public_suffix_list.splitlines()

    # Try to keep custom information from the previous list
    if custom_list.is_file():
        with open(custom_list, "r") as f:
            prev_custom_list = f.read()
            prev_custom_list_lines = prev_custom_list.splitlines()
    else:
        custom_list.parent.mkdir(parents=True, exist_ok=True)
        with open(custom_list, "w") as f:
            f.write(public_suffix_list)
            f.write("\n")
            custom_lines = [
                "// ===BEGIN CUSTOM DOMAINS===",
                "// Comment out domains above to disable IANA or Mozilla TLDs.",
                "// During update, this section will be kept and will attempt to keep commented out IANA/Mozilla domains.",
                "// Add custom Mozilla style TLDs below",
                "",
                "// My local TLDs",
                "// local",
                "// mycompany.local",
                "",
                "// ===END CUSTOM DOMAINS===",
            ]
            for line in custom_lines:
                f.write(line)
                f.write("\n")
        return

    # Skip the header
    while "===BEGIN ICANN DOMAINS===" not in prev_custom_list_lines[0]:
        prev_custom_list_lines.pop(0)

    prev_comments = {}
    prev_line = ""
    for line in prev_custom_list_lines:
        if line.startswith("//") and prev_line == "":
            tld_header = True
        else:
            tld_header = False
        if line.startswith("//") and not tld_header:
            prev_comments[line.lstrip("/").strip()] = line.strip()
        prev_line = line.strip()

    # Drop IANA and Mozilla content from the previous custom list
    while "===BEGIN CUSTOM DOMAINS===" not in prev_custom_list_lines[0]:
        prev_custom_list_lines.pop(0)

    with open(custom_list, "w") as f:
        file_header = True
        prev_line = "None"
        for line in public_suffix_list_lines:
            if "===BEGIN ICANN DOMAINS===" in line:
                file_header = False

            if line.startswith("//") and prev_line == "":
                tld_header = True
            else:
                tld_header = False

            prev_line = line.strip()

            # Write header
            if file_header:
                f.write(line)
                f.write("\n")
                continue

            # Keep previous commented out domains
            if not tld_header and line.strip() in prev_comments:
                f.write(prev_comments[line])
                f.write("\n")
                continue

            # Write other lines
            f.write(line)
            f.write("\n")

        # Write custom domains
        f.write("\n")
        f.writelines(line + "\n" for line in prev_custom_list_lines)


def update_mozilla_list(public_suffix_list):
    """Updates Mozilla Public Suffix List and Custom Suffix List if the Public Suffix List is out of date."""

    local_config_dir = Path(__file__).resolve().parents[1] / "local"
    if not local_config_dir.is_dir():
        local_config_dir.mkdir()

    mozilla_path = local_config_dir / "public_suffix_list.dat"
    custom_list_path = local_config_dir / "public_suffix_list_custom.dat"

    # If the files are old, update Mozilla Public Suffix List and Custom List
    logger.info("Attempting to update Mozilla Public Suffix List.")

    # Write the downloaded list to the custom list
    with open(mozilla_path, "w") as f:
        f.write(public_suffix_list)
    logger.info(
        "Wrote Mozilla Public Suffix List to app's local/public_suffix_list.dat"
    )

    # Update the custom list
    update_custom_list(custom_list_path, public_suffix_list)
    logger.info(
        "Wrote Custom Public Suffix List to app's local/public_suffix_list_custom.dat"
    )


def update_iana_list(iana_tlds=None):
    """Updates IANA TLD List."""

    local_config_dir = Path(__file__).resolve().parents[1] / "local"
    if not local_config_dir.is_dir():
        local_config_dir.mkdir()

    iana_path = local_config_dir / "tlds-alpha-by-domain.txt"

    logger.info("Attempting to update IANA TLD list.")

    logger.info("Downloaded IANA TLDs")

    with open(iana_path, "w") as f:
        f.write(iana_tlds)
        logger.info(f"Wrote IANA TLDs to {iana_path}")

    logger.info("Wrote IANA TLDs to app's local/tlds-alpha-by-domain.txt ")


def update_all():
    psl_url = iana_url = create_lookup = None
    try:
        config_str = sys.stdin.read()
        logger.info(config_str)

        # parse the config XML
        doc = xml.dom.minidom.parseString(config_str)
        root = doc.documentElement

        conf_node = root.getElementsByTagName("configuration")[0]
        if not conf_node:
            logging.error("No configuration found in input")
            return ""

        stanza = conf_node.getElementsByTagName("stanza")[0]
        if not stanza:
            logging.error("No stanza found in input")
            return ""

        stanza_name = stanza.getAttribute("name")
        if not stanza_name:
            logging.error("No stanza name found in input")
            return ""

        params = stanza.getElementsByTagName("param")
        for param in params:
            param_name = param.getAttribute("name")
            if (
                param_name
                and param.firstChild
                and param.firstChild.nodeType == param.firstChild.TEXT_NODE
            ):
                data = param.firstChild.data.strip()
                if not data:
                    continue
                if param_name == "PSL_URL":
                    psl_url = data
                if param_name == "IANA_URL":
                    iana_url = data
                if param_name == "create_lookup":
                    create_lookup = data

    except Exception as e:
        raise Exception("Error getting Splunk configuration via STDIN: %s" % str(e))

    if create_lookup and create_lookup.lower() in ["1", "true", "t", "yes", "y"]:
        create_lookup = True

    try:
        public_suffix_list = download_psl(psl_url=psl_url)
        update_mozilla_list(public_suffix_list)
    except Exception as e:
        logger.error("Failed to update PSL with error: %s" % str(e))

    try:
        iana_tlds = download_iana(iana_url=iana_url)
        update_iana_list(iana_tlds)
    except Exception as e:
        logger.error("Failed to update IANA TLD list with error: %s" % str(e))

    if create_lookup:
        try:
            logger.info("Generating PSL lookup CSV file.")
            generate_lookup()
        except Exception as e:
            logger.error("Failed to generate PSL lookup file with error: %s" % str(e))

    return ""


# Script must implement these args: scheme, validate-arguments
if __name__ == "__main__":
    if len(sys.argv) > 1:
        if sys.argv[1] == "--scheme":
            do_scheme()
        elif sys.argv[1] == "--validate-arguments":
            validate_arguments()
        else:
            pass
    else:
        update_all()

    sys.exit(0)
