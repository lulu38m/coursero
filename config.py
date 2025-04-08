import os

class Config:
    SQLALCHEMY_DATABASE_URI = "mysql://admin:Password@172.16.77.148:3306/coursero_db"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SECRET_KEY = os.urandom(24)
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
