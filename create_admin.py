
from getpass import getpass

from app import app
from models import db, Admin


with app.app_context():

    username = input("Enter admin username: ").strip()

    if not username:
        print("Username cannot be empty.")

    elif Admin.query.filter_by(username=username).first():
        print("This admin username already exists.")

    else:
        password = getpass("Enter admin password: ")
        confirm = getpass("Confirm admin password: ")

        if len(password) < 8:
            print("Password must contain at least 8 characters.")

        elif password != confirm:
            print("Passwords do not match.")

        else:
            admin = Admin(username=username)
            admin.set_password(password)

            db.session.add(admin)
            db.session.commit()

            print("Admin account created successfully!")
