#!/usr/bin/env python3
"""
Smart Wordlist Generator
Creates complex password variations based on keywords, including permutations,
case changes, and special prefixes for acronyms.
"""
import itertools
import argparse

# Default ordinal prefixes to add to acronyms.
DEFAULT_ORDINAL_PREFIXES = ['1st', '2nd', '3rd', 'First', 'Second', 'Third']

def generate_numeric_sequences(max_length=1):
    """Generates simple numeric sequences (e.g., '0', '1', '2'...)."""
    sequences = ['']  # Include empty string for cases with no prefix/suffix.
    if max_length == 0:
        return sequences
    digits = '0123456789'
    for length in range(1, max_length + 1):
        for seq_tuple in itertools.product(digits, repeat=length):
            sequences.append(''.join(seq_tuple))
    return sequences

def is_acronym(word):
    """Checks if a word is likely an acronym (all uppercase letters)."""
    return word.isalpha() and word.isupper()

def get_smart_variants(word, ordinals):
    """Generates case variations and adds ordinal prefixes to acronyms."""
    variants = {word.lower(), word.capitalize(), word.upper()}
    if is_acronym(word):
        for prefix in ordinals:
            if prefix:  # Avoid adding an empty prefix twice.
                variants.add(prefix + word)
                variants.add(prefix + word.capitalize())
    return list(variants)

def generate_wordlist(words, prefixes, infixes, suffixes, ordinals):
    """The main wordlist generation engine."""
    wordlist = set()

    # 1. Generate smart variants for each individual keyword.
    variants_per_word = [get_smart_variants(w, ordinals) for w in words]

    # 2. Generate all permutations of the keywords to try every order.
    for perm_indices in itertools.permutations(range(len(words))):
        permuted_variants = [variants_per_word[i] for i in perm_indices]

        # 3. Create all possible combinations of these variants.
        for variant_combo in itertools.product(*permuted_variants):
            # A) Handle single-word variants.
            if len(variant_combo) == 1:
                base_word = variant_combo[0]
                for p in prefixes:
                    for s in suffixes:
                        wordlist.add(p + base_word + s)
            # B) Handle multi-word combinations.
            else:
                # B.1 - Direct concatenation (e.g., "PassWord").
                joined_direct = "".join(variant_combo)
                for p in prefixes:
                    for s in suffixes:
                        wordlist.add(p + joined_direct + s)

                # B.2 - Joined with infixes (e.g., "Pass-Word", "Pass_Word").
                for infix_combo in itertools.product(infixes, repeat=len(variant_combo) - 1):
                    # Weave the words and infixes together.
                    result = [None] * (len(variant_combo) + len(infix_combo))
                    result[::2] = variant_combo
                    result[1::2] = infix_combo
                    joined_infix = "".join(result)
                    
                    for p in prefixes:
                        for s in suffixes:
                            wordlist.add(p + joined_infix + s)

    return sorted(list(wordlist))

def main():
    """Parses arguments and runs the wordlist generator."""
    default_numerics = generate_numeric_sequences(1)

    parser = argparse.ArgumentParser(
        description="Smart Wordlist Generator based on keywords.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument('--keywords', nargs='+', required=True, help='One or more base keywords (e.g., "admin" "company" "FBI").')
    parser.add_argument('--outfile', default='custom_wordlist.txt', help='Output filename for the generated wordlist.')
    
    parser.add_argument('--prefixes', nargs='*', default=[''] + default_numerics, help='List of prefixes.')
    parser.add_argument('--infixes', nargs='*', default=['', '_' ,'@','-'], help='List of infixes to join keywords.')
    parser.add_argument('--suffixes', nargs='*', default=['', '!', '123'] + default_numerics, help='List of suffixes.')
    parser.add_argument('--ordinals', nargs='*', default=DEFAULT_ORDINAL_PREFIXES, help='Ordinal prefixes for acronyms.')

    args = parser.parse_args()

    print("[*] Generating wordlist...")
    result = generate_wordlist(args.keywords, args.prefixes, args.infixes, args.suffixes, args.ordinals)

    try:
        with open(args.outfile, 'w', encoding='utf-8') as f:
            for word in result:
                f.write(word + '\n')
        print(f"[+] Generated {len(result):,} unique passwords and saved to {args.outfile}")
    except IOError as e:
        print(f"[!] Error writing to file: {e}")

if __name__ == '__main__':
    main()
