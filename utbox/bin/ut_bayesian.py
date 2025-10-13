import csv
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Dict, Tuple

import ut_log_lib

logger = ut_log_lib.setup_logger()


def ngram_split(word, length) -> Counter:
    """
    ngram_split("google", 2) => {'go':1, 'oo':1, 'og':1, 'gl':1, 'le':1}
    ngram_split("toronto", 2) => {'to': 2, 'or': 1, 'ro': 1, 'on': 1, 'nt': 1}
    """

    return Counter([word[i : i + length] for i in range(len(word) - length + 1)])


def load_file(f_path, gram_max=4) -> Tuple[int, Dict[int, Counter]]:
    entries = 0
    all_grams = {}

    for i in range(2, gram_max + 1):
        all_grams[i] = Counter()

    with open(f_path, newline="") as f:
        logger.debug(f"Loading {f_path}")
        reader = csv.reader(f)
        header = next(reader)
        word_idx = header.index("word")

        for line in reader:
            word = line[word_idx].lower().strip()
            for i in range(2, gram_max + 1):
                all_grams[i].update(ngram_split(word, i))
            entries += 1

    return entries, all_grams


def bayes_score(
    word,
    n_good: int,
    set_good_dict: dict[int, Counter],
    n_bad: int,
    set_bad_dict: dict[int, Counter],
    gram_size=2,
) -> float:
    """
    Compute the naive bayesian score - Probability that the domain is a bad one knowing it's ngrams.
    Actually limited to 2-grams for now
    """

    set_good = set_good_dict[gram_size]
    set_bad = set_bad_dict[gram_size]

    p_total = 1.0
    p_total_inv = 1.0

    grams = ngram_split(word, gram_size)
    for g in grams:

        if not g in set_bad or not g in set_good:
            continue

        # probability that the gram X appears in bad domains
        prob_g_bad = n_bad * set_bad[g]

        # probability that the gram X appears in good domains
        prob_g_good = n_good * set_good[g]

        # probability that a domain is a bad one, knowing that the gram X is in it;
        prob = prob_g_bad / (prob_g_bad + prob_g_good)

        p_total *= prob
        p_total_inv *= 1 - prob

    return p_total / (p_total + p_total_inv)


def load_bayesian_counts(
    ngram_max=4,
) -> tuple[int, int, dict[int, Counter], dict[int, Counter]]:
    lookup_path = Path(__file__).resolve().parents[1] / "lookups"

    bayesian_good = lookup_path / "ut_bayesian_good.csv"
    (n_good, set_good) = load_file(bayesian_good, gram_max=ngram_max)

    bayesian_bad = lookup_path / "ut_bayesian_bad.csv"
    (n_bad, set_bad) = load_file(bayesian_bad, gram_max=ngram_max)

    return n_bad, n_good, set_bad, set_good


########
# MAIN #
########
def main():
    ngram_max = 4
    n_bad, n_good, set_bad, set_good = load_bayesian_counts()

    header = ["word", "ut_bayesian"]

    csv_in = csv.DictReader(sys.stdin)  # use the first line as the CSV header
    csv_out = csv.DictWriter(sys.stdout, header)
    csv_out.writeheader()  # write header

    for row in csv_in:
        word = row["word"].lower().strip()
        ut_bayesian = {}
        for i in range(2, ngram_max + 1):
            ut_bayesian[i] = bayes_score(
                word, n_good, set_good, n_bad, set_bad, gram_size=i
            )
        row["ut_bayesian"] = json.dumps({"ut_bayesian": ut_bayesian})

        # return row to Splunk
        csv_out.writerow(row)


if __name__ == "__main__":
    main()
