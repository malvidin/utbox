import csv
import json
import sys

import ut_log_lib
import ut_presets_lib

########
# MAIN #
########
logger = ut_log_lib.setup_logger()


def main():
    header = ["word", "set", "ut_suites"]

    csv_in = csv.DictReader(sys.stdin)  # use the first line as header
    csv_out = csv.DictWriter(sys.stdout, header)
    csv_out.writeheader()  # write header

    for row in csv_in:
        try:
            word = row["word"].strip()
            wordset = row["set"].strip()

            counts = ut_presets_lib.suites(word, wordset)

            row["ut_suites"] = json.dumps(counts)

        except Exception as e:
            logger.info(str(e))

        # return row to Splunk
        csv_out.writerow(row)


if __name__ == "__main__":
    main()
