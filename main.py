import tkinter as tk
from tkinter import filedialog, messagebox


from ttkthemes import ThemedTk
from tkinter import ttk
import sqlite3
import bcrypt

conn = sqlite3.connect('users.db')
c = conn.cursor()


# Create the users table if it doesn't exist
c.execute('''CREATE TABLE IF NOT EXISTS users
             (id INTEGER PRIMARY KEY AUTOINCREMENT,
              username TEXT NOT NULL,
              password TEXT NOT NULL)''')



def show_encryption_frame():
    encryption_frame.grid(row=0, column=1, sticky="nsew")
    decryption_frame.grid_remove()
    analysis_frame.grid_remove()


def show_decryption_frame():
    decryption_frame.grid(row=0, column=1, sticky="nsew")
    encryption_frame.grid_remove()
    analysis_frame.grid_remove()


def show_analysis_frame():
    analysis_frame.grid(row=0, column=1, sticky="nsew")
    encryption_frame.grid_remove()
    decryption_frame.grid_remove()


def show_login_frame():
    login_frame.grid(row=0, column=1, sticky="nsew")
    encryption_frame.grid_remove()
    decryption_frame.grid_remove()
    analysis_frame.grid_remove()
    register_frame.grid_remove()


def show_register_frame():
    register_frame.grid(row=0, column=1, sticky="nsew")
    encryption_frame.grid_remove()
    decryption_frame.grid_remove()
    analysis_frame.grid_remove()
    login_frame.grid_remove()


def show_main_buttons_frame():
    main_buttons_frame.grid(row=0, column=0, sticky="nsew")
    encryption_frame.grid_remove()
    decryption_frame.grid_remove()
    analysis_frame.grid_remove()
    login_frame.grid_remove()
    auth_buttons_frame.grid_remove()


def show_database():
    # Create a new window
    database_window = tk.Toplevel(root)
    database_window.title("Database")

    # Create a Treeview widget
    tree = ttk.Treeview(database_window)
    tree.pack(fill=tk.BOTH, expand=True)

    # Retrieve data from the database
    c.execute("SELECT * FROM users")
    rows = c.fetchall()

    # Define tree columns
    tree["columns"] = ("ID", "Username", "Password")

    # Format tree columns
    tree.column("#0", width=0, stretch=tk.NO)
    tree.column("ID", anchor=tk.CENTER, width=50)
    tree.column("Username", anchor=tk.CENTER, width=150)
    tree.column("Password", anchor=tk.CENTER, width=150)

    # Create tree headings
    tree.heading("#0", text="", anchor=tk.CENTER)
    tree.heading("ID", text="ID", anchor=tk.CENTER)
    tree.heading("Username", text="Username", anchor=tk.CENTER)
    tree.heading("Password", text="Password", anchor=tk.CENTER)

    # Insert data into the treeview
    for row in rows:
        tree.insert("", tk.END, values=row)

    # Run the new window's main event loop
    database_window.mainloop()


def login():
    username = entry_username_login.get()
    password = entry_password_login.get()
    # Check if the user exists in the database
    c.execute("SELECT password FROM users WHERE username=?", (username,))
    result = c.fetchone()

    if result:
        hashed_password = result[0]
        if bcrypt.checkpw(password.encode('utf-8'), hashed_password):
            messagebox.showinfo("Login", "Login successful!")
            show_main_buttons_frame()
        else:
            messagebox.showerror("Login", "Invalid username or password!")
    else:
        messagebox.showerror("Login", "Invalid username or password!")


def register():
    username = entry_username_register.get()
    password = entry_password_register.get()

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
    conn.commit()
    messagebox.showinfo("Register", "Registration successful!")
    show_login_frame()


root = ThemedTk(theme="breeze")
root.title("Intro to Cryptography")
root.geometry("310x360")



# Create encryption, decryption, and analysis label frames
encryption_frame = ttk.LabelFrame(root, text="Encryption")
decryption_frame = ttk.LabelFrame(root, text="Decryption")
analysis_frame = ttk.LabelFrame(root, text="Analysis")
login_frame = ttk.LabelFrame(root, text="Login")
register_frame = ttk.LabelFrame(root, text="Register")


# Set grid configurations for root and frames
root.grid_rowconfigure(0, weight=1)
root.grid_columnconfigure(0, weight=0)
root.grid_columnconfigure(1, weight=1)

encryption_frame.grid(row=0, column=1, sticky="nsew", padx=5, pady=5)
decryption_frame.grid(row=0, column=1, sticky="nsew", padx=5, pady=5)
analysis_frame.grid(row=0, column=1, sticky="nsew", padx=5, pady=5)
login_frame.grid(row=0, column=1, sticky="nsew", padx=5, pady=5)
register_frame.grid(row=0, column=1, sticky="nsew", padx=5, pady=5)


# Create Encryption widgets
ttk.Label(encryption_frame, text="Plain Text").grid(row=0, column=0, pady=5)
encrypt_entry = ttk.Entry(encryption_frame)
encrypt_entry.grid(row=1, column=0, pady=5, padx=10)

encrypt_button = ttk.Button(encryption_frame, text="Encrypt", command='')
encrypt_button.grid(row=2, column=0, pady=5)

# Create Decryption widgets
ttk.Label(decryption_frame, text="Secret Message").grid(row=0, column=0, pady=5)
decrypt_entry = ttk.Entry(decryption_frame)
decrypt_entry.grid(row=1, column=0, pady=5, padx=10)

decrypt_button = ttk.Button(decryption_frame, text="Decrypt", command='')
decrypt_button.grid(row=2, column=0, pady=5)


# Create login widgets
ttk.Label(login_frame, text="User Name:").grid(row=0, column=0, pady=5)
entry_username_login = ttk.Entry(login_frame)
entry_username_login.grid(row=1, column=0, pady=5, padx=10)

ttk.Label(login_frame, text="Password").grid(row=2, column=0, pady=5)
entry_password_login = ttk.Entry(login_frame)
entry_password_login.grid(row=3, column=0, pady=5, padx=10)

submit_button_login = ttk.Button(login_frame, text="Login", command=login)
submit_button_login.grid(row=4, column=0, pady=5, padx=10)

# Create Register widgets
ttk.Label(register_frame, text="User Name:").grid(row=0, column=0, pady=5)
entry_username_register = ttk.Entry(register_frame)
entry_username_register.grid(row=1, column=0, pady=5, padx=10)

ttk.Label(register_frame, text="Password").grid(row=2, column=0, pady=5)
entry_password_register = ttk.Entry(register_frame)
entry_password_register.grid(row=3, column=0, pady=5, padx=10)

submit_button_register = ttk.Button(register_frame, text="Register", command=register)
submit_button_register.grid(row=4, column=0, pady=5, padx=10)

# Create main buttons frame
main_buttons_frame = ttk.LabelFrame(root, text="Main Buttons")
main_buttons_frame.grid(row=0, column=0, sticky="ns", padx=5, pady=5)

# Create buttons to switch between frames
encryption_button = ttk.Button(main_buttons_frame, text="Encryption", command=show_encryption_frame)
encryption_button.pack(padx=10, pady=10, fill=tk.X)

decryption_button = ttk.Button(main_buttons_frame, text="Decryption", command=show_decryption_frame)
decryption_button.pack(padx=10, pady=10, fill=tk.X)

analyze_button = ttk.Button(main_buttons_frame, text="Analyze", command=show_analysis_frame)
analyze_button.pack(padx=10, pady=10, fill=tk.X)

database_button = ttk.Button(main_buttons_frame, text="Database", command=show_database)
database_button.pack(padx=10, pady=10, fill=tk.X)

# Create Auth Label Frame
auth_buttons_frame = ttk.LabelFrame(root, text="Authentication")
auth_buttons_frame.grid(row=0, column=0, sticky="ns", padx=5, pady=5)

login_button = ttk.Button(auth_buttons_frame, text="Login", command=show_login_frame)
login_button.pack(padx=10, pady=10, fill=tk.X)

register_button = ttk.Button(auth_buttons_frame, text="Register", command=show_register_frame)
register_button.pack(padx=10, pady=10, fill=tk.X)

root.mainloop()