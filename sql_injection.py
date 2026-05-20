import sqlite3
import mysql.connector
import psycopg2

# SQL Injection via string formatting
def get_user_by_name(username):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchall()

# SQL Injection via % formatting
def get_user_by_id(user_id):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE id = %s" % user_id
    cursor.execute(query)
    return cursor.fetchall()

# SQL Injection via f-string
def delete_user(user_id):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute(f"DELETE FROM users WHERE id = {user_id}")
    conn.commit()

# SQL Injection in login
def login(username, password):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    cursor.execute(query)
    return cursor.fetchone()

# SQL Injection with mysql connector
def update_email(user_id, email):
    conn = mysql.connector.connect(host="localhost", user="root", password="root", database="app")
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET email = '" + email + "' WHERE id = " + str(user_id))
    conn.commit()

# Second-order SQL injection
def search_products(search_term):
    conn = sqlite3.connect("products.db")
    cursor = conn.cursor()
    query = "SELECT * FROM products WHERE name LIKE '%" + search_term + "%'"
    cursor.execute(query)
    return cursor.fetchall()
