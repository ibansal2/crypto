import sqlite3

def register():
    username = input("Enter username: ")
    password = ""
    password_verify = " "
    while password != password_verify:
        password = input("Enter password: ")
        password_verify = input("Re-enter password: ")
        if password != password_verify:
            print("Passwords do not match. Please try again.")

    db = sqlite3.connect("users.db")
    cursor = db.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS users (username TEXT, password TEXT)")
    cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
    db.commit()
    
    print(f"User {username} registered successfully.")

    #Store username and password in database