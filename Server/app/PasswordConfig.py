#This is a class definition in Python that has the same constants as the Java interface
# PasswordConfig. In Python, constants are typically defined as class variables.
# Note that Python doesn't have the final keyword like Java, so we can omit it. Also, in Python,
# we don't need to define the access modifiers like public.

class PasswordConfig:
    PASS_MIN_LENGTH = 10
    PASS_MAX_LENGTH = 18
    HISTORY = 3
    MAX_TRIES_LOGIN = 3

    UPPERCASE = True
    LOWERCASE = True
    DIGITS = True
    SPECIAL = True

    PREVENT_DICTIONARY = True

    DICTIONARY_FILE = "darkwebdictionary.txt"

    SERVER_EMAIL = "comltd@outlook.co.il"
