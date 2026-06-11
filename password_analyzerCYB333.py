# password_analyzer.py
# CYB333 - Password Strength Analyzer
# A basic program that checks how strong a password is and gives feedback.
# It looks at the length, the kinds of characters used, and whether the
# password is on a short list of very common passwords.

# A short list of passwords that show up in almost every breach.
# If the user types one of these, it is automatically weak.
common_passwords = [
    "password", "password1", "123456", "12345678", "qwerty",
    "abc123", "111111", "iloveyou", "admin", "letmein",
    "welcome", "monkey", "dragon", "football", "sunshine"
]


def check_password(password):
    # Start the score at 0 and add points for good things.
    score = 0
    feedback = []

    # Check 1: length
    if len(password) >= 12:
        score = score + 2
    elif len(password) >= 8:
        score = score + 1
    else:
        feedback.append("Too short. Use at least 8 characters, 12 or more is better.")

    # Check 2: does it have a lowercase letter?
    has_lower = False
    has_upper = False
    has_digit = False
    has_symbol = False

    # Go through each character and see what type it is.
    for char in password:
        if char.islower():
            has_lower = True
        elif char.isupper():
            has_upper = True
        elif char.isdigit():
            has_digit = True
        else:
            # Anything that is not a letter or number we count as a symbol.
            has_symbol = True

    # Add a point for each type of character that is present.
    if has_lower:
        score = score + 1
    else:
        feedback.append("Add a lowercase letter.")

    if has_upper:
        score = score + 1
    else:
        feedback.append("Add an uppercase letter.")

    if has_digit:
        score = score + 1
    else:
        feedback.append("Add a number.")

    if has_symbol:
        score = score + 1
    else:
        feedback.append("Add a symbol like ! or ?.")

    # Check 3: is it a common password?
    if password.lower() in common_passwords:
        feedback.append("This is a very common password and would be cracked instantly.")
        score = 0   # reset to 0 because a common password is always weak

    return score, feedback


def rating(score):
    # Turn the number score into a word.
    if score <= 2:
        return "Weak"
    elif score <= 4:
        return "Medium"
    else:
        return "Strong"


# Main part of the program.
# Keep asking for passwords until the user just presses Enter on a blank line.
while True:
    password = input("Enter a password to check (or press Enter to quit): ")

    # If the user typed nothing, stop the loop.
    if password == "":
        print("Goodbye.")
        break

    score, feedback = check_password(password)

    print("")
    print("Score:", score, "out of 6")
    print("Strength:", rating(score))

    # Print the feedback, if there is any.
    if feedback:
        print("Suggestions:")
        for tip in feedback:
            print(" -", tip)
    else:
        print("Good password. No suggestions.")

    print("")   # blank line before the next prompt
