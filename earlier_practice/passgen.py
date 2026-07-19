# Import Necessary Libraries for password generating application
import random
import string

# Creat a function
def generate_password(length: int = 10): # Telling the function to take Integer as an input, 10 is the default
    alphabet = string.ascii_letters + string.digits + string.punctuation # combine all ascii, digits and special characters and stored it in alphabet character
    password = ''.join(random.choice(alphabet) for i in range (length)) # Select random characters stored in alphabet variable in with the length variable values, without any sperator ('')
    return password  # return the result to password


password = generate_password(16)
print(f"Your Password is :{password}")
