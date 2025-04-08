from app import db, login_manager
from flask_login import UserMixin
from datetime import datetime

@login_manager.user_loader
def load_user(user_id):
    user = User.query.get(int(user_id))
    # Ajoutez un log pour vérifier que l'utilisateur est bien chargé
    print("Chargement de l'utilisateur pour id:", user_id, "=>", user)
    return user

class User(db.Model, UserMixin):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    fullname = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

    def __repr__(self):
        return f"<User {self.email}>"

class Submission(db.Model):
    __tablename__ = 'submission'
    id = db.Column(db.Integer, primary_key=True)
    course = db.Column(db.String(100), nullable=False)
    exercise = db.Column(db.String(100), nullable=False)
    language = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(50), default='queue', nullable=False)
    score = db.Column(db.Integer, default=0, nullable=False)
    submission_date = db.Column(db.DateTime, default=datetime.utcnow)
