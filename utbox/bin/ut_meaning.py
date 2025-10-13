import csv
import re
import sys
from collections import defaultdict
from pathlib import Path

import ut_log_lib

logger = ut_log_lib.setup_logger()

"""
Module that compute a ratio between the word length and the length of it's known composing words
Use the wordlist meaning.dic (one word per line). This list is loaded once per batch of 50,000
events (Splunk Internal behavior on custom search commands).

microsoft = micro + soft (2 words in meaning.dic) => ratio = 1
microxyze = micro + xyze (1 word in meaning.dic)  => ratio = 5/9 (len('micro')/len('microsoft'))

This is a very naive algorithm, this should be improved.
"""


def load_word_list(f_path):

    word_dict = defaultdict(set)

    with open(f_path, newline="") as f:
        logger.debug(f"Loading {f_path}")
        reader = csv.reader(f)
        header = next(reader)
        word_idx = header.index("word")

        for line in reader:
            word = line[word_idx].lower().strip()
            word_len = len(word)

            word_dict[word_len].add(re.compile(word))

    return word_dict


def meaning(word_list, word):

    word = word.lower()
    word_len = len(word)
    s_len = 0

    for i in range(word_len, 0, -1):
        if not i in word_list:
            continue

        for preg_t in word_list[i]:

            if preg_t.search(word):
                word = preg_t.sub(".", word)
                s_len += i

    ratio = 0.0
    if s_len:
        ratio = float(s_len) / float(word_len)

    return ratio


########
# MAIN #
########
def main():
    meaning_path = Path(__file__).resolve().parents[1] / "lookups" / "ut_meaning.csv"
    word_list = load_word_list(meaning_path)

    header = ["word", "ut_meaning_ratio"]

    csv_in = csv.DictReader(sys.stdin)  # use the first line as the CSV header
    csv_out = csv.DictWriter(sys.stdout, header)
    csv_out.writeheader()  # write header

    for row in csv_in:
        word = row["word"].strip()

        row["ut_meaning_ratio"] = meaning(word_list, word)

        # return row to Splunk
        csv_out.writerow(row)


if __name__ == "__main__":
    main()
