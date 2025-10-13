import re
import string
from collections import Counter
from typing import Dict

set_az = set(string.ascii_lowercase)
set_AZ = set(string.ascii_uppercase)
set_Az = set(string.ascii_letters)
set_vowels = set("AEIOUYaeiouy")
set_09 = set(string.digits)
set_hex = set(string.hexdigits)
set_printable = set(string.printable) - set(string.whitespace)
set_typographic = set("&*@\\^#%~_|")

PRESETS = {
    "@punct@": set_printable - set_Az - set_09,
    "@typo@": set_typographic,
    "@digits@": set_09,
    "@alpha@": set_az,
    "@alpha_up@": set_AZ,
    "@alpha_all@": set_Az,
    "@alphanum@": set_az ^ set_09,
    "@alphanum_up@": set_AZ ^ set_09,
    "@alphanum_all@": set_Az ^ set_09,
    "@hexa@": set_hex - set_AZ,
    "@hexa_up@": set_hex - set_az,
    "@hexa_all@": set_hex,
    "@noalpha@": set_printable - set_Az,
    "@base64@": set_Az ^ set_09 ^ set("+/="),
    "@base64url@": set_Az ^ set_09 ^ set("-_="),
    "@vowels@": set_vowels - set_AZ,
    "@vowels_up@": set_vowels - set_az,
    "@vowels_all@": set_vowels,
    "@consonants@": set_az - set_vowels,
    "@consonants_up@": set_AZ - set_vowels,
    "@consonants_all@": set_Az - set_vowels,
}

PATTERNS = {}

for p_name, p_chars in PRESETS.items():
    re_str = f"([{re.escape(''.join(sorted(p_chars)))}]+)"
    PATTERNS[p_name] = re.compile(re_str)


def count_set(word, word_set) -> Counter:
    # @word@ is a special set which means that only the letters composing the submitted word are counted.
    if word_set == "@word@":
        set_chars = sorted(set(word))
    else:
        if word_set in PRESETS:
            set_chars = PRESETS[word_set]
        else:
            set_chars = set(word_set)

    counter = Counter([f"{ord(c):X}" for c in word if c in set_chars])
    counter_sum = sum(c for c in counter.values())
    counter.update({"sum": counter_sum})

    return counter


def suites(word, word_set) -> Dict[str, int]:
    # some of the preset have no meaning here (like @word@)

    ret = {}

    set_names = [s.strip() for s in word_set.split(",") if s.strip() in PRESETS]

    for s in set_names:
        preg = PATTERNS[s]
        parts = preg.findall(word)

        if parts:
            max_len = max([len(p) for p in parts])
        else:
            max_len = 0

        label = s.strip("@")
        ret[f"ut_max_suite_{label}"] = max_len

    return ret
