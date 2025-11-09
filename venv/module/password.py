from zxcvbn import zxcvbn
import bcrypt
from getpass import getpass


def check_strength(password : str) -> str:
    result = zxcvbn(password)
    score = result["score"]

    if score == 4:
        response = "Very strong password: score of 4"
    elif score == 3:
        response = "Strong enough password: score of 3"
    else :
        feedback = result.get('feedback')
        warning = feedback.get('warning')
        suggestions = feedback.get('suggestions')

        response = f'Weak password: score of {str(score)}\nWarning: {warning}'
        response += "\nSuggestions: "
        for suggestion in suggestions:
            response += " " + suggestion
    return response

def hash_pw(password : str) -> bytes:
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode(), salt)
    return hashed

def verify_password(pw_attempt : bytes, hashed : bytes) -> str:
    if bcrypt.checkpw(pw_attempt.encode(), hashed):
        return "Password is correct. Access granted!"
    return "Incorrect password. Access denied."

if __name__ == "__main__":
    while True:
        password = getpass("Enter a password to check strength: ")
        print(check_strength(password))
        if check_strength(password).startswith("Weak"):
            print("Please choose a straonger password.")
        else:
            break
    
    hash_password = hash_pw(password)
    print(f'Hashed password: {hash_password}')

    attempt = getpass("Re-enter the password to verify: ")
    print(verify_password(attempt, hash_password))