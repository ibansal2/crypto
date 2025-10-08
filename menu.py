import register

process = input("1. Register\n2. Log In\n3. Exit\n")
if process == "1":
    register.register()
elif process == "2":
    register() # Placeholder for login function - use key derivation fns to store pwds (PBKDF2)
    #
elif process == "3":
    exit()
else:
    print("Invalid option. Please try again.")






1