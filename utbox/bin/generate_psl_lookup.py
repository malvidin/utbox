import csv
from collections import defaultdict
from pathlib import Path


def _parse_psl_line(line):
    """Parse a PSL line and extract domain metadata."""
    clean_line = line
    wildcard = False
    exception = False

    if clean_line.startswith("*."):
        wildcard = True
        clean_line = clean_line.lstrip("*.")

    if clean_line.startswith("!"):
        exception = True
        clean_line = clean_line.lstrip("!")

    tld = "." not in line

    return clean_line, wildcard, exception, tld


def _calculate_match_depth(clean_line, wildcard, exception):
    """Calculate the minimum match depth for a domain entry."""
    # Assumed wildcard depth, like "*.com" for the "com" entry, plus 1 for each additional label.
    match_depth = clean_line.count(".") + 2
    # For wildcard items, it needs one more label than the item includes.
    # For example, *.kobe.jp means that it must match *.*.kobe.jp and contain 4 labels.
    match_depth += wildcard
    # For exception items, it can match the exact label as well as subdomains.
    # For example, !city.kobe.jp means that it must match city.kobe.jp and contain 3 or more labels.
    match_depth -= exception

    return match_depth


def _create_lookup_entries(line, clean_line, match_depth, domain_type):
    """Create lookup entries for both wildcard and bare domain formats."""
    entries = []

    for domain_wc in (f"*.{clean_line}", f"{clean_line.lstrip('*.')}"):
        entries.append(
            {
                "domain": line,
                "domain_wc": domain_wc,
                "match_depth": str(match_depth),
                "domain_type": domain_type,
            }
        )

    return entries


def _write_lookup_csv(sorted_lookup_entries, psl_lookup):
    """Write the lookup dictionary to a CSV file."""
    # Sort the keys, reversed, so the first match will be the most specific.
    sort_order_vals = sorted(sorted_lookup_entries.keys(), reverse=True)

    with open(psl_lookup, "w", newline="") as f:
        header = ["domain", "domain_wc", "match_depth", "domain_type", "sort_order"]
        writer = csv.DictWriter(f, fieldnames=header)
        writer.writeheader()

        for sort_order in sort_order_vals:
            for lookup_data in sorted_lookup_entries[sort_order]:
                lookup_data["sort_order"] = sort_order
                writer.writerow(lookup_data)


def generate_lookup():
    app_path = Path(__file__).resolve().parents[1]
    psl_default = app_path / "default" / "public_suffix_list.dat"
    psl_local = app_path / "local" / "public_suffix_list.dat"
    psl_lookup = app_path / "lookups" / "ut_psl_lookup.csv"

    if psl_local.is_file():
        public_suffix_list = psl_local.read_text()
    else:
        public_suffix_list = psl_default.read_text()

    # See _write_lookup_csv() for the order of the fields in the CSV:
    # "domain", "domain_wc", "match_depth", "domain_type", "sort_order"
    sorted_lookup_entries = defaultdict(list)

    domain_section = "ICANN"
    for i, line in enumerate(public_suffix_list.splitlines()):
        line = line.strip()

        if line.startswith("// ===BEGIN PRIVATE DOMAINS==="):
            # Set the domain type to private when entering the private section of the Public Suffix List
            domain_section = "PRIVATE"

        if line.startswith("//") or not line.strip():
            # Skip comments and empty lines
            continue

        clean_line, wildcard, exception, tld = _parse_psl_line(line)
        match_depth = _calculate_match_depth(clean_line, wildcard, exception)
        sort_order = clean_line.count(".") + exception
        domain_type = "TLD" if tld else domain_section

        clean_lines = [clean_line]

        if not clean_line.isascii():
            clean_lines.append(clean_line.encode("idna").decode("utf-8"))

        for clean_line in clean_lines:
            entries = _create_lookup_entries(line, clean_line, match_depth, domain_type)
            sorted_lookup_entries[sort_order].extend(entries)

    # Add wildcard for "Accept Unknown" style matches
    sorted_lookup_entries[-1].extend(["*.*", "UNKNOWN", "*.*", "2", "-1"])

    _write_lookup_csv(sorted_lookup_entries, psl_lookup)


def main():
    generate_lookup()


if __name__ == "__main__":
    main()
