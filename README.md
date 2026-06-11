# Password Strength Analyzer

This is a small Python program I wrote for CYB333. It checks how strong a password is and tells you what is wrong with it. It looks at the length, what kinds of characters are used, and whether the password is on a short list of very common passwords.

It only uses the Python standard library, so there is nothing to install.

## What it checks

- **Length** - 8 characters gets some credit, 12 or more gets full credit.
- **Character types** - lowercase, uppercase, a number, and a symbol. It adds a point for each one it finds.
- **Common passwords** - if the password is on a short list of well-known ones (like "password" or "qwerty"), it is marked weak no matter what else it has.

## How to run it

```
python password_analyzer.py
```

It will ask you to type a password. Then it prints a score out of 6, a rating of Weak, Medium, or Strong, and a list of suggestions for anything it is missing.

Example run:

```
Enter a password to check: Hello123

Score: 4 out of 6
Strength: Medium
Suggestions:
 - Add a symbol like ! or ?.
```

## How the score works

The program starts the score at 0 and adds points:

- up to 2 points for length
- 1 point each for having a lowercase letter, an uppercase letter, a number, and a symbol

That makes 6 the highest score. If the password is one of the common ones, the score is reset to 0 because a common password is always easy to guess.

- 0 to 2 = Weak
- 3 to 4 = Medium
- 5 to 6 = Strong

## Why I built it this way

I kept it simple on purpose. The point was to practice the basics: a `for` loop to go through each character, `if/else` checks, and a couple of small functions. I followed the general advice from NIST and OWASP that length and avoiding common passwords matter more than fancy rules, but I did not try to copy a full professional tool.

## Notes

This is a basic class project, not a real security tool. A real one would check against a much bigger list of breached passwords and would never see the password in plain text. This one just runs locally and does not save anything you type.

## References

National Institute of Standards and Technology. (2024). *Digital identity guidelines: Authentication and authenticator management* (NIST Special Publication 800-63B). https://pages.nist.gov/800-63-4/sp800-63b.html

OWASP Foundation. (2024). *Authentication cheat sheet.* https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html

Author: Rodolfo Duarte
