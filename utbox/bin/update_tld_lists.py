import re
from datetime import datetime, timedelta
from pathlib import Path

import sys

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


def download_psl() -> str:
    # Download the latest public suffix list
    resp = requests.get("https://publicsuffix.org/list/public_suffix_list.dat")
    resp.raise_for_status()
    public_suffix_list = resp.text

    # Verify the downloaded list
    assert (
        "===BEGIN ICANN DOMAINS===" in public_suffix_list[:2000]
    ), "Downloaded list does not appear to be a valid Mozilla PSL file."

    return public_suffix_list


def download_iana() -> str:
    # Download the latest IANA list
    resp = requests.get("https://data.iana.org/TLD/tlds-alpha-by-domain.txt")
    resp.raise_for_status()
    iana_list = resp.text

    # Verify the downloaded list
    assert re.match(
        r"# Version \d+, Last Updated", iana_list[:2000]
    ), "Downloaded list does not appear to be a valid IANA TLD list."

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
        with open (custom_list, "w") as f:
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


def update_mozilla_list(max_age_days=30):
    """Updates Mozilla Public Suffix List and Custom Suffix List if the Public Suffix List is out of date."""
    date_now = datetime.now()

    default_config_dir = Path(__file__).resolve().parents[1] / "default"
    local_config_dir = Path(__file__).resolve().parents[1] / "local"
    if not local_config_dir.is_dir():
        local_config_dir.mkdir()

    mozilla_default_path = default_config_dir / "public_suffix_list.dat"
    mozilla_path = local_config_dir / "public_suffix_list.dat"
    custom_list_path = local_config_dir / "public_suffix_list_custom.dat"

    update_mozilla = True

    # If the files are old, update Mozilla Public Suffix List and Custom List
    valid_paths = [p for p in [mozilla_path, mozilla_default_path] if p.is_file()]
    if valid_paths:
        last_mod_time = max(p.stat().st_mtime for p in valid_paths)
        last_mod_date = datetime.fromtimestamp(last_mod_time)
        if date_now - last_mod_date < timedelta(days=max_age_days):
            # No update needed
            update_mozilla = False
            logger.info("Mozilla list is up to date.")
        else:
            logger.info("Mozilla list is out of date, attempting to update.")

    if update_mozilla:
        public_suffix_list = download_psl()

        # Write the downloaded list to the custom list
        with open(mozilla_path, "w") as f:
            f.write(public_suffix_list)

        # Update the custom list
        update_custom_list(custom_list_path, public_suffix_list)

    return update_mozilla


def update_iana_list(max_age_days=30):
    """Updates IANA TLD List if it is out of date."""
    date_now = datetime.now()

    default_config_dir = Path(__file__).resolve().parents[1] / "default"
    local_config_dir = Path(__file__).resolve().parents[1] / "local"
    if not local_config_dir.is_dir():
        local_config_dir.mkdir()

    iana_default_path = default_config_dir / "tlds-alpha-by-domain.txt"
    iana_path = local_config_dir / "tlds-alpha-by-domain.txt"

    update_iana = True

    # If the files are old, update IANA TLD List
    valid_paths = [p for p in [iana_path, iana_default_path] if p.is_file()]
    if valid_paths:
        last_mod_time = max(p.stat().st_mtime for p in valid_paths)
        last_mod_date = datetime.fromtimestamp(last_mod_time)
        if date_now - last_mod_date < timedelta(days=max_age_days):
            # No update needed
            update_iana = False
            logger.info("IANA list is up to date.")
        else:
            logger.info("IANA list is out of date, attempting to update.")

    if update_iana:
        iana_tlds = download_iana()
        logger.info("Downloaded IANA TLDs")

        with open(iana_path, "w") as f:
            f.write(iana_tlds)
            logger.info(f"Wrote IANA TLDs to {iana_path}")

    return update_iana


def update_all(max_age_days: int):
    logger.info("Updating lists over max age of %s days.", max_age_days)
    update_mozilla_list(max_age_days=max_age_days)
    update_iana_list(max_age_days=max_age_days)


def main():
    update_mozilla_list()
    update_iana_list()


if __name__ == "__main__":
    main()
