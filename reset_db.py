# reset_db.py
from app import db, app

with app.app_context():
    print("Dropping all tables...")
    db.drop_all()
    print("Creating tables fresh...")
    db.create_all()
    print("Database has been reset ✅")

