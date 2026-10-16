import os


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'oto-reboot-secret-key-change-me')
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///oto_reboot.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SCHEDULER_API_ENABLED = True
    MONITOR_INTERVAL = int(os.environ.get('MONITOR_INTERVAL', 300))  # seconds
    SSH_TIMEOUT = int(os.environ.get('SSH_TIMEOUT', 10))
    PING_TIMEOUT = int(os.environ.get('PING_TIMEOUT', 3))
