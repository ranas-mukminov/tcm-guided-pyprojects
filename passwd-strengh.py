print("--- Password Strength Checker ---")
passwd = input("Enter your password: ")
if len(passwd) < 8:
    print("Password is weak, must be at least 8 characters.")
else:
    print("Password is strong.")
    
