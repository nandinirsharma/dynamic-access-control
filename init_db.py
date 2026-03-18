# init_db.py
from db import init_db, create_user, get_user_by_username
from auth import hash_password

def seed():
    print("Initializing DB...")
    init_db()
    # create test users
    if not get_user_by_username("alice"):
        create_user("alice", hash_password("alicepass"))
        print("Created user alice / alicepass")
    if not get_user_by_username("admin"):
        create_user("admin", hash_password("adminpass"))
        print("Created admin / adminpass")
    print("Done.")

if __name__ == "__main__":
    seed()
