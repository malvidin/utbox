import csv
import json
import sys

import ut_presets_lib


########
# MAIN #
########
def main():
    header = ["word", "set", "ut_countset"]

    csv_in = csv.DictReader(sys.stdin)  # use the first line as the CSV header
    csv_out = csv.DictWriter(sys.stdout, header)
    csv_out.writeheader()  # write header

    for row in csv_in:
        word = row["word"].strip()

        wordset = row["set"].strip()

        countset = ut_presets_lib.count_set(word, wordset)

        row["ut_countset"] = json.dumps({"ut_countset": countset})

        # return row to Splunk
        csv_out.writerow(row)


if __name__ == "__main__":
    main()
