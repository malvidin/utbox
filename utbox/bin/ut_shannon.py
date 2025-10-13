import csv
import math
import sys
from collections import Counter

import ut_log_lib

"""
This lookup compute the shannon entropy.
http://en.wikipedia.org/wiki/Entropy_%28information_theory%29
"""

logger = ut_log_lib.setup_logger()


#############
# FUNCTIONS #
#############
def shannon(word):
    if isinstance(word, str):
        word = word.encode("utf-8")

    if len(word) in (0, 1):
        return 0.0

    counter = Counter(word)
    if len(counter) == 1:
        return 0.0

    length = sum(counter.values())
    proportions = [count / length for count in counter.values()]
    entropy = 0.0
    for proportion in proportions:
        entropy -= proportion * math.log(proportion, 2)

    return entropy


########
# MAIN #
########
def main():
    header = ["word", "ut_shannon"]

    csv_in = csv.DictReader(sys.stdin)  # use the first line as header
    csv_out = csv.DictWriter(sys.stdout, header)
    csv_out.writeheader()  # write header

    for row in csv_in:
        word = row["word"].strip()

        row["ut_shannon"] = shannon(word)

        # return row to Splunk
        csv_out.writerow(row)


if __name__ == "__main__":
    main()
