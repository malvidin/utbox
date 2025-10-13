import csv
import sys


#############
# FUNCTIONS #
#############
def levenshtein(s1: str, s2: str) -> int:

    # s1 must be longer than s2
    if len(s1) < len(s2):
        s1, s2 = s2, s1

    # len(s1) >= len(s2)
    if len(s2) == 0:
        return len(s1)

    s1 = s1.lower()
    s2 = s2.lower()

    if s2 in s1:
        return len(s1) - len(s2)

    previous_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            # j + 1 instead of j since previous_row and current_row are one character longer than s2
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))

        previous_row = current_row

    return previous_row[-1]


########
# MAIN #
########
def main():
    header = ["word1", "word2", "ut_levenshtein"]

    csv_in = csv.DictReader(sys.stdin)  # use the first line as the CSV header
    csv_out = csv.DictWriter(sys.stdout, header)
    csv_out.writeheader()  # write header

    for row in csv_in:
        word1 = row["word1"].strip()
        word2 = row["word2"].strip()

        row["ut_levenshtein"] = levenshtein(word1, word2)

        # return row to Splunk
        csv_out.writerow(row)


if __name__ == "__main__":
    main()
