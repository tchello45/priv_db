import sqlite3
import json
import os
import rsa
import jwt

if os.path.exists("priv_db_config.json"):
    with open("priv_db_config.json") as f:
        config = json.load(f)
        db_folder = config["db_folder"]
    del config
    del f
else:
    db_folder = "db/"
if not os.path.exists(db_folder):
    os.mkdir(db_folder)
level_int_dict = {
    0: "block",
    1: "common",
    2: "moderator",
    3: "vip",
    4: "vip+",
    5: "fr1p",
    6: "beta",
    7: "logger", 
    8: "admin"
}
level_str_dict = {
    "block": 0,
    "common": 1,
    "moderator": 2,
    "vip": 3,
    "vip+": 4,
    "fr1p": 5,
    "beta": 6,
    "logger": 7,
    "admin": 8
}
if not os.path.isfile("public_key.pem") and not os.path.isfile("private_key.pem"):
    print("Generating keys...")
    (public_key, private_key) = rsa.newkeys(4096)
    print("Keys generated.")   
    with open("public_key.pem", "wb") as f:
        f.write(public_key.save_pkcs1())
    with open("private_key.pem", "wb") as f:
        f.write(private_key.save_pkcs1())
    print("Keys saved.")
    print("Keys loaded.")
else:
    with open("public_key.pem", "rb") as f:
        public_key = rsa.PublicKey.load_pkcs1(f.read())
    with open("private_key.pem", "rb") as f:
        private_key = rsa.PrivateKey.load_pkcs1(f.read())
    print("Keys loaded.")

class tokens:
    @staticmethod
    def generate_token(username:str, priv_level:int) -> str:
        return jwt.encode({'username': username, 'priv_lvl': priv_level}, private_key.save_pkcs1(), algorithm='RS256')
    @staticmethod
    def validate_token(token:str, username:str, priv_level:int) -> bool:
        try:
            decoded = jwt.decode(token, public_key.save_pkcs1(), algorithms='RS256')
        except:
            return False
        if decoded['username'] != username or decoded['priv_lvl'] != priv_level:
            return False
        return True
class main_db:
    def __init__(self, path:str="main.priv_db") -> None:
        """Path: Path to the main database"""
        self.path = path
        self.conn = sqlite3.connect(path)
        self.c = self.conn.cursor()
        self.c.execute("CREATE TABLE IF NOT EXISTS users (username TEXT, server_id TEXT)")
        self.conn.commit()
    def add_user(self, username:str, server_id:str) -> None:
        self.c.execute("SELECT * FROM users WHERE username=?", (username,))
        if self.c.fetchone() is not None:
            raise ValueError("User already exists")
        self.c.execute("INSERT INTO users VALUES (?, ?)", (username, server_id))
        self.conn.commit()
    def remove_user(self, username:str) -> None:
        self.c.execute("SELECT * FROM users WHERE username=?", (username,))
        if self.c.fetchone() is None:
            raise ValueError("User does not exist")
        self.c.execute("DELETE FROM users WHERE username=?", (username,))
        self.conn.commit()
    def get_user_server_id(self, username:str) -> str:
        self.c.execute("SELECT * FROM users WHERE username=?", (username,))
        user = self.c.fetchone()
        if user is None:
            raise ValueError("User does not exist")
        return user[1]
    def exists(self, username:str) -> bool:
        self.c.execute("SELECT * FROM users WHERE username=?", (username,))
        return self.c.fetchone() is not None
    def get_all_users(self) -> list:
        self.c.execute("SELECT * FROM users")
        return self.c.fetchall()

class user_db:
    def __init__(self, server_id:str) -> None:
        self.server_id = server_id
        self.path = db_folder + server_id + ".priv_db"
        self.conn = sqlite3.connect(self.path)
        self.c = self.conn.cursor()
        self.c.execute("CREATE TABLE IF NOT EXISTS users (username TEXT, priv_level INTEGER, token TEXT)")
        self.conn.commit()
    def add_user(self, username:str, priv_level:int=1) -> None:
        if priv_level not in level_int_dict:
            raise ValueError("Invalid priv_level")
        if priv_level == 1 or priv_level == 0:
            token = None
        else:
            token = tokens.generate_token(username, priv_level)
        self.c.execute("SELECT * FROM users WHERE username=?", (username,))
        if self.c.fetchone() is not None:
            raise ValueError("User already exists")
        self.c.execute("INSERT INTO users VALUES (?, ?, ?)", (username, priv_level, token))
        self.conn.commit()
    def remove_user(self, username:str) -> None:
        self.c.execute("SELECT * FROM users WHERE username=?", (username,))
        if self.c.fetchone() is None:
            raise ValueError("User does not exist")
        self.c.execute("DELETE FROM users WHERE username=?", (username,))
        self.conn.commit()
    def get_user(self, username:str) -> tuple:
        self.c.execute("SELECT * FROM users WHERE username=?", (username,))
        user = self.c.fetchone()
        if user is None:
            raise ValueError("User does not exist")
        return user
    

