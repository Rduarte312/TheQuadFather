#!/usr/bin/env python3
"""
password_analyzer.py
====================

A heuristic, privacy-preserving password strength analyzer.

This module evaluates the strength of a candidate password against a set of
well-documented weakness classes (insufficient length, breach/dictionary
membership, repeated characters, numeric/alphabetic sequences, keyboard-walk
patterns, and predictable "decorator" endings such as ``123``, ``!``, or a
year) and returns a 0-100 score, a five-tier verdict, and clear, actionable
feedback that tells the user *why* a password is weak and *how* to improve it.

Design philosophy
-----------------
Modern guidance (NIST SP 800-63B Rev. 4, 2025; OWASP Authentication Cheat
Sheet) has moved away from rigid "LUDS" composition mandates (lower, upper,
digit, symbol) toward two ideas that actually predict guessability:

    1.  Length / entropy is the dominant factor.
    2.  A password must NOT appear on a blocklist of common, expected, or
        breached values, and must not be built from trivially guessable
        patterns (sequences, repeats, keyboard walks, dates).

This analyzer therefore treats composition as advisory only, while the score
is driven primarily by length-adjusted entropy with explicit *penalties* for
guessable structure -- conceptually mirroring pattern-matching estimators such
as Dropbox's zxcvbn (Wheeler, 2016).

Privacy guarantees
------------------
*   No password is ever written to disk, logged, cached, or transmitted.
*   The password lives only in local process memory for the duration of a
    single evaluation and is never persisted.
*   Interactive input uses ``getpass`` so the password is not echoed to the
    terminal or stored in shell history.

Usage
-----
As a CLI::

    python password_analyzer.py            # secure, masked prompt
    python password_analyzer.py --show      # echo input (testing only)

As a library::

    from password_analyzer import analyze_password, PasswordAnalyzer

    report = analyze_password("Tr0ub4dor&3")
    print(report.score, report.rating)
    for tip in report.feedback:
        print(tip)

Optional enhancements (graceful fallbacks if absent)
----------------------------------------------------
*   If the third-party ``zxcvbn`` package is installed, its crack-time
    estimate is surfaced alongside the heuristic score (``pip install zxcvbn``).
*   If an external wordlist file (e.g. a rockyou-style list) is supplied via
    ``--wordlist PATH`` or the ``PWA_WORDLIST`` environment variable, it
    augments the built-in common-password blocklist.

Author: (your name)
License: MIT
"""

from __future__ import annotations

import argparse
import math
import os
import re
import sys
from dataclasses import dataclass, field
from typing import Optional

# --------------------------------------------------------------------------- #
# 1. CONFIGURATION / TUNABLE CONSTANTS
# --------------------------------------------------------------------------- #
# All thresholds are gathered here so a reviewer can adjust policy in one place
# without hunting through the logic. Values reflect NIST SP 800-63B Rev. 4.

# NIST SP 800-63B Rev. 4 (2025): single-factor minimum is 15 chars; an absolute
# floor of 8 is the bare minimum even when used as part of MFA. We treat 12 as
# a practical "good" length and 15+ as fully compliant.
MIN_ABSOLUTE_LENGTH = 8       # below this is automatically Very Weak
RECOMMENDED_LENGTH = 12       # "good" everyday length
NIST_SINGLE_FACTOR_LENGTH = 15  # NIST single-factor recommendation
MAX_USEFUL_LENGTH = 64        # OWASP/NIST recommend accepting at least this

# Score band boundaries (0-100) mapped to the five-tier verdict.
RATING_BANDS = [
    (0, 20, "Very Weak"),
    (20, 40, "Weak"),
    (40, 60, "Moderate"),
    (60, 80, "Strong"),
    (80, 101, "Very Strong"),
]

# Years that commonly appear as suffixes (e.g. "...2024"). We treat any 4-digit
# run in the plausible birth/recent range as a "year" decorator.
YEAR_PATTERN = re.compile(r"(19\d{2}|20\d{2})")

# Common single-/double-character "decorator" endings appended to satisfy
# naive composition rules (e.g. "password1", "summer!", "hello123").
COMMON_ENDINGS = ["123", "1234", "12345", "!", "@", "#", "1", "01", "00", "!!", "1!"]

# Keyboard adjacency rows used to detect "keyboard walks" such as "qwerty",
# "asdf", or "zxcvbn". Detection is case-insensitive and bidirectional.
KEYBOARD_ROWS = [
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
    "1234567890",
    # common diagonal / shifted walks
    "qazwsxedc",
    "1qaz2wsx",
]

# A compact, in-script blocklist of the most common breached passwords and
# base words. This is intentionally small (NIST notes excessively large lists
# yield diminishing returns for online attacks); it can be augmented with an
# external wordlist for thoroughness. Source inspiration: annual "most common
# passwords" reports and the SecLists / rockyou corpus.
COMMON_PASSWORDS = {
    "password", "passw0rd", "password1", "123456", "12345678", "123456789",
    "1234567890", "qwerty", "qwertyuiop", "abc123", "111111", "123123",
    "000000", "iloveyou", "admin", "letmein", "welcome", "monkey", "dragon",
    "football", "baseball", "master", "shadow", "superman", "michael",
    "sunshine", "princess", "trustno1", "starwars", "whatever", "freedom",
    "ninja", "azerty", "login", "solo", "test", "guest", "root", "changeme",
    "secret", "summer", "winter", "spring", "autumn", "hello", "hottie",
    "loveme", "zaq12wsx", "qazwsx", "default", "user", "pass",
}

# Common dictionary base words frequently used as the "core" of a weak password.
# Used for substring detection after stripping decorators.
COMMON_BASE_WORDS = {
    "password", "welcome", "admin", "login", "dragon", "monkey", "shadow",
    "master", "superman", "batman", "soccer", "hockey", "ranger", "computer",
    "summer", "winter", "spring", "autumn", "love", "money", "hello", "secret",
    "google", "apple", "microsoft", "amazon", "company", "school", "office",
}


# --------------------------------------------------------------------------- #
# 2. RESULT DATA STRUCTURE
# --------------------------------------------------------------------------- #
@dataclass
class StrengthReport:
    """Structured result returned by :func:`analyze_password`.

    Attributes
    ----------
    score:
        Final 0-100 strength score (higher is stronger).
    rating:
        Five-tier human verdict ("Very Weak" ... "Very Strong").
    entropy_bits:
        Estimated Shannon entropy in bits based on character-set size and
        length (an upper bound; real guessability is usually lower).
    length:
        Password length in characters.
    issues:
        Machine-readable list of detected weakness codes.
    feedback:
        Human-readable, actionable suggestions explaining each issue.
    crack_time:
        Optional human crack-time string if the ``zxcvbn`` library is present.
    """

    score: int
    rating: str
    entropy_bits: float
    length: int
    issues: list[str] = field(default_factory=list)
    feedback: list[str] = field(default_factory=list)
    crack_time: Optional[str] = None


# --------------------------------------------------------------------------- #
# 3. THE ANALYZER
# --------------------------------------------------------------------------- #
class PasswordAnalyzer:
    """Encapsulates all password-evaluation heuristics.

    The class is deliberately stateless with respect to the password itself:
    a password is passed to :meth:`analyze`, evaluated, and discarded. Only
    configuration (thresholds, optional wordlist) is held on the instance, so
    the same analyzer can be reused safely across many evaluations.
    """

    def __init__(self, extra_wordlist: Optional[set[str]] = None) -> None:
        # Merge the built-in blocklist with any externally supplied wordlist.
        self.common_passwords: set[str] = set(COMMON_PASSWORDS)
        if extra_wordlist:
            self.common_passwords |= {w.lower() for w in extra_wordlist}

    # ----------------------------- character sets ------------------------- #
    @staticmethod
    def _charset_size(password: str) -> int:
        """Estimate the size of the character pool the password draws from.

        Used for the Shannon-entropy upper bound: entropy = length * log2(pool).
        This is the classic NIST-era model; it overestimates real strength for
        structured passwords, which is exactly why we apply pattern penalties
        afterward.
        """
        pool = 0
        if re.search(r"[a-z]", password):
            pool += 26
        if re.search(r"[A-Z]", password):
            pool += 26
        if re.search(r"\d", password):
            pool += 10
        # Any non-alphanumeric printable character counts toward a symbol pool.
        if re.search(r"[^A-Za-z0-9]", password):
            pool += 33  # approx. count of printable ASCII symbols + space
        return pool

    @classmethod
    def _entropy_bits(cls, password: str) -> float:
        """Shannon entropy upper bound in bits: L * log2(pool size)."""
        pool = cls._charset_size(password)
        if pool <= 1 or not password:
            return 0.0
        return len(password) * math.log2(pool)

    # ----------------------------- pattern checks ------------------------- #
    @staticmethod
    def _has_repeats(password: str, run: int = 3) -> bool:
        """True if any character repeats ``run`` or more times in a row.

        Example: "aaab" or "1111". Repeats sharply reduce real entropy because
        a guesser models them with a single token plus a count.
        """
        return re.search(r"(.)\1{" + str(run - 1) + r",}", password) is not None

    @staticmethod
    def _has_sequence(password: str, length: int = 3) -> bool:
        """Detect ascending or descending runs of digits or letters.

        Covers "123" / "321" / "abc" / "cba". A sliding window checks whether
        ``length`` consecutive characters differ by a constant +1 or -1 in
        their code points (within the same alphabet/number class).
        """
        s = password.lower()
        for i in range(len(s) - length + 1):
            window = s[i : i + length]
            if not (window.isalpha() or window.isdigit()):
                continue
            diffs = {ord(window[j + 1]) - ord(window[j]) for j in range(len(window) - 1)}
            if diffs == {1} or diffs == {-1}:  # strictly ascending or descending
                return True
        return False

    @staticmethod
    def _has_keyboard_walk(password: str, length: int = 4) -> bool:
        """Detect substrings that walk along a physical keyboard row.

        Example: "qwert", "asdf", "zxcvbn". Both forward and reversed walks of
        at least ``length`` characters are flagged.
        """
        s = password.lower()
        for row in KEYBOARD_ROWS:
            rev = row[::-1]
            for i in range(len(row) - length + 1):
                seg = row[i : i + length]
                if seg in s or seg[::-1] in s or rev[i : i + length] in s:
                    return True
        return False

    @staticmethod
    def _has_year(password: str) -> bool:
        """True if the password contains a plausible 4-digit year (19xx/20xx)."""
        return YEAR_PATTERN.search(password) is not None

    @staticmethod
    def _has_common_ending(password: str) -> bool:
        """True if the password ends with a predictable decorator.

        Catches the classic "make it comply" tricks: a trailing "123", "!",
        "1", or a year appended to a base word.
        """
        lower = password.lower()
        if any(lower.endswith(end) for end in COMMON_ENDINGS):
            return True
        # A trailing year is also a predictable ending.
        return YEAR_PATTERN.search(password[-4:]) is not None

    def _is_common_password(self, password: str) -> bool:
        """Blocklist membership test (exact, case-insensitive)."""
        return password.lower() in self.common_passwords

    def _contains_common_word(self, password: str) -> bool:
        """Detect a common dictionary base word inside the password.

        We strip leading/trailing decorators (digits and symbols) first so that
        "P@ssw0rd2024!" still reduces to the base "password".
        """
        # Normalise common leetspeak substitutions to expose the base word.
        leet = (password.lower()
                .replace("@", "a").replace("0", "o").replace("1", "i")
                .replace("3", "e").replace("$", "s").replace("!", "i"))
        stripped = re.sub(r"^[^a-z]+|[^a-z]+$", "", leet)
        for word in COMMON_BASE_WORDS:
            if word in stripped and len(word) >= 4:
                return True
        return False

    # ----------------------------- composition ---------------------------- #
    @staticmethod
    def _composition(password: str) -> dict[str, bool]:
        """Report which character classes are present (advisory only)."""
        return {
            "lower": bool(re.search(r"[a-z]", password)),
            "upper": bool(re.search(r"[A-Z]", password)),
            "digit": bool(re.search(r"\d", password)),
            "symbol": bool(re.search(r"[^A-Za-z0-9]", password)),
        }

    # ----------------------------- optional zxcvbn ------------------------ #
    @staticmethod
    def _zxcvbn_crack_time(password: str) -> Optional[str]:
        """If the optional ``zxcvbn`` package is installed, return its
        human-readable offline-slow-hashing crack-time estimate. Otherwise
        return ``None`` so the analyzer remains fully functional without it.
        """
        try:
            from zxcvbn import zxcvbn  # type: ignore
        except Exception:
            return None
        try:
            result = zxcvbn(password)
            return str(
                result["crack_times_display"]["offline_slow_hashing_1e4_per_second"]
            )
        except Exception:
            return None

    # ----------------------------- main entry point ----------------------- #
    def analyze(self, password: str) -> StrengthReport:
        """Evaluate ``password`` and return a :class:`StrengthReport`.

        Scoring model
        --------------
        We start from a length-and-entropy base score, then subtract penalties
        for each guessable pattern detected. This mirrors the reality that a
        long password built from a predictable pattern (e.g. "abcabcabcabc")
        is far weaker than its raw entropy suggests. The score is finally
        clamped to the 0-100 range and mapped to a five-tier verdict.
        """
        issues: list[str] = []
        feedback: list[str] = []

        length = len(password)
        entropy = self._entropy_bits(password)
        comp = self._composition(password)

        # Empty input is trivially Very Weak.
        if length == 0:
            return StrengthReport(0, "Very Weak", 0.0, 0,
                                  ["empty"], ["Password is empty."])

        # ---- Base score from entropy (capped contribution at ~70 pts) ---- #
        # ~60 bits of entropy is widely considered the threshold for a strong
        # human-memorable password; we map that to roughly the top of the band.
        base = min(70.0, (entropy / 60.0) * 70.0)

        # ---- Length handling ------------------------------------------- #
        if length < MIN_ABSOLUTE_LENGTH:
            issues.append("too_short")
            feedback.append(
                f"Too short ({length} chars). Use at least "
                f"{RECOMMENDED_LENGTH}-{NIST_SINGLE_FACTOR_LENGTH} characters; "
                "NIST recommends 15+ for single-factor use."
            )
            base -= 25
        elif length < RECOMMENDED_LENGTH:
            feedback.append(
                f"Acceptable but short ({length} chars). Aim for "
                f"{RECOMMENDED_LENGTH}+ characters; a memorable passphrase is ideal."
            )
        elif length >= NIST_SINGLE_FACTOR_LENGTH:
            base += 10  # reward meeting the NIST single-factor recommendation

        # ---- Blocklist / dictionary membership ------------------------- #
        if self._is_common_password(password):
            issues.append("breached_common")
            feedback.append(
                "This is one of the most common breached passwords. It would "
                "be cracked instantly. Choose something unique and unrelated."
            )
            base -= 60  # dominant penalty: blocklisted = effectively broken

        if self._contains_common_word(password):
            issues.append("dictionary_word")
            feedback.append(
                "Built around a common dictionary word. Attackers try these "
                "first. Combine several unrelated words or use a passphrase."
            )
            base -= 15

        # ---- Structural / predictable patterns ------------------------- #
        if self._has_repeats(password):
            issues.append("repeated_chars")
            feedback.append(
                "Contains 3+ repeated characters in a row (e.g. 'aaa', '111'). "
                "Repetition adds little real strength."
            )
            base -= 12

        if self._has_sequence(password):
            issues.append("sequence")
            feedback.append(
                "Contains a predictable sequence such as '123', '321', or "
                "'abc'. Sequences are among the first things a cracker tries."
            )
            base -= 15

        if self._has_keyboard_walk(password):
            issues.append("keyboard_walk")
            feedback.append(
                "Contains a keyboard pattern (e.g. 'qwerty', 'asdf', 'zxcvbn'). "
                "These are highly predictable -- avoid keyboard walks."
            )
            base -= 15

        if self._has_year(password):
            issues.append("year")
            feedback.append(
                "Contains a year (e.g. a birth year or recent year). Dates are "
                "easily guessed; avoid embedding them."
            )
            base -= 8

        if self._has_common_ending(password):
            issues.append("predictable_ending")
            feedback.append(
                "Ends with a predictable decorator like '123', '!', '1', or a "
                "year. These are exactly the patterns crackers append "
                "automatically -- they add almost no strength."
            )
            base -= 10

        # ---- Composition diversity (advisory bonus, not a mandate) ----- #
        classes_present = sum(comp.values())
        if classes_present <= 1 and length < NIST_SINGLE_FACTOR_LENGTH:
            feedback.append(
                "Uses only one type of character. While length matters more "
                "than composition, mixing character types still helps for "
                "shorter passwords."
            )
            base -= 8
        else:
            # Small bonus for diversity, scaled so it can never dominate length.
            base += (classes_present - 1) * 3

        # ---- Finalise score and verdict -------------------------------- #
        score = int(max(0, min(100, round(base))))
        rating = self._rating_for(score)

        # ---- Positive reinforcement when nothing is wrong -------------- #
        if not issues and score >= 80:
            feedback.append(
                "Strong choice -- long and free of predictable patterns. "
                "Store it in a password manager and enable MFA where available."
            )
        elif not feedback:
            feedback.append("No major weaknesses detected, but longer is always better.")

        crack_time = self._zxcvbn_crack_time(password)

        return StrengthReport(
            score=score,
            rating=rating,
            entropy_bits=round(entropy, 1),
            length=length,
            issues=issues,
            feedback=feedback,
            crack_time=crack_time,
        )

    @staticmethod
    def _rating_for(score: int) -> str:
        """Map a 0-100 score to its five-tier verdict label."""
        for low, high, label in RATING_BANDS:
            if low <= score < high:
                return label
        return "Very Strong"


# --------------------------------------------------------------------------- #
# 4. CONVENIENCE FUNCTION (library entry point)
# --------------------------------------------------------------------------- #
def analyze_password(
    password: str, extra_wordlist: Optional[set[str]] = None
) -> StrengthReport:
    """One-shot helper: analyze a single password and return its report.

    This is the recommended import for other code::

        from password_analyzer import analyze_password
        report = analyze_password("correct horse battery staple")
    """
    return PasswordAnalyzer(extra_wordlist=extra_wordlist).analyze(password)


# --------------------------------------------------------------------------- #
# 5. OPTIONAL EXTERNAL WORDLIST LOADING
# --------------------------------------------------------------------------- #
def load_wordlist(path: str, limit: int = 100_000) -> set[str]:
    """Load up to ``limit`` entries from an external wordlist file.

    The file is read with errors ignored (breach corpora often contain invalid
    bytes) and is never modified. Only the in-memory set is returned; nothing
    is written back to disk.
    """
    words: set[str] = set()
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            for i, line in enumerate(fh):
                if i >= limit:
                    break
                token = line.strip().lower()
                if token:
                    words.add(token)
    except OSError as exc:
        print(f"[warning] could not read wordlist '{path}': {exc}", file=sys.stderr)
    return words


# --------------------------------------------------------------------------- #
# 6. PRESENTATION HELPERS (CLI only)
# --------------------------------------------------------------------------- #
def _bar(score: int, width: int = 20) -> str:
    """Render a simple ASCII strength meter for the terminal."""
    filled = int(round(score / 100 * width))
    return "[" + "#" * filled + "-" * (width - filled) + f"] {score}/100"


def _print_report(report: StrengthReport) -> None:
    """Pretty-print a :class:`StrengthReport` to stdout."""
    print()
    print("=" * 52)
    print("  PASSWORD STRENGTH ANALYSIS")
    print("=" * 52)
    print(f"  Rating       : {report.rating}")
    print(f"  Score        : {_bar(report.score)}")
    print(f"  Length       : {report.length} characters")
    print(f"  Entropy (est): {report.entropy_bits} bits")
    if report.crack_time:
        print(f"  Crack time   : ~{report.crack_time} (zxcvbn, offline slow hash)")
    print("-" * 52)
    if report.feedback:
        print("  Feedback:")
        for tip in report.feedback:
            # Wrap long feedback lines for readability.
            print(f"   - {tip}")
    print("=" * 52)
    print()


# --------------------------------------------------------------------------- #
# 7. COMMAND-LINE INTERFACE
# --------------------------------------------------------------------------- #
def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="password_analyzer",
        description="Privacy-preserving password strength analyzer "
                    "(no password is ever stored or logged).",
    )
    parser.add_argument(
        "--show",
        action="store_true",
        help="Echo the typed password (TESTING ONLY -- defeats input masking).",
    )
    parser.add_argument(
        "--wordlist",
        metavar="PATH",
        default=os.environ.get("PWA_WORDLIST"),
        help="Optional external wordlist (e.g. a rockyou-style file) to "
             "augment the built-in blocklist. May also be set via the "
             "PWA_WORDLIST environment variable.",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Analyze a single password and exit (default loops until blank).",
    )
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    """CLI entry point. Returns a process exit code."""
    args = _build_arg_parser().parse_args(argv)

    # Load optional external wordlist (in memory only).
    extra: Optional[set[str]] = None
    if args.wordlist:
        extra = load_wordlist(args.wordlist)
        if extra:
            print(f"[info] loaded {len(extra):,} entries from external wordlist.")

    analyzer = PasswordAnalyzer(extra_wordlist=extra)

    print("Password Strength Analyzer  (Ctrl-C or blank line to quit)")
    print("Your input is NOT stored, logged, or written to any file.\n")

    # Import getpass lazily so the module stays importable in odd environments.
    import getpass

    while True:
        try:
            if args.show:
                pwd = input("Enter a password to analyze: ")
            else:
                pwd = getpass.getpass("Enter a password to analyze (hidden): ")
        except (KeyboardInterrupt, EOFError):
            print("\nGoodbye.")
            return 0

        if pwd == "":
            print("Goodbye.")
            return 0

        report = analyzer.analyze(pwd)
        _print_report(report)

        # Critical: drop the reference to the password immediately.
        del pwd, report

        if args.once:
            return 0


if __name__ == "__main__":
    raise SystemExit(main())
