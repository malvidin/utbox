import csv
import sys

import update_tld_lists
import ut_log_lib
import ut_parse_lib

########
# MAIN #
########

logger = ut_log_lib.setup_logger()


def main():
    header = [
        "url",
        "list",
        "ut_scheme",
        "ut_netloc",
        "ut_path",
        "ut_params",
        "ut_query",
        "ut_fragment",
        "ut_domain",
        "ut_tld",
        "ut_domain_without_tld",
        "ut_subdomain",
        "ut_port",
        "ut_subdomain_parts",
        "ut_subdomain_count",
    ]

    try:
        update_tld_lists.update_all(max_age_days=30)
    except Exception as e:
        logger.error("Failed to update TLD lists with error: %s" % str(e))

    csv_in = csv.DictReader(sys.stdin)  # use the first line as the CSV header
    csv_out = csv.DictWriter(sys.stdout, header)
    csv_out.writeheader()  # write header

    psl_names = ["iana", "icann", "mozilla", "custom"]
    psl_options = {}
    for l in psl_names:
        try:
            psl_options[l] = ut_parse_lib.get_public_suffix_list(l)
        except Exception as e:
            logger.error("Failed to load TLD list %s with error: %s" % (str(l), str(e)))

    for row in csv_in:
        if "url" not in row:
            continue

        url = row["url"].strip()

        list_name = row.get("list", "").strip().lower()
        if list_name not in psl_names:
            label, psl = next(iter(psl_options.items()))
            logger.warning("List name %s not found, using list %s" % (list_name, label))
        else:
            psl = psl_options[list_name]

        try:
            res = ut_parse_lib.parse_extended(url, psl)
            row.update(res)
        except Exception as e:
            logger.error("Got error %s on with url %s" % (str(e), url))

        # return row to Splunk
        csv_out.writerow(row)


if __name__ == "__main__":
    main()
