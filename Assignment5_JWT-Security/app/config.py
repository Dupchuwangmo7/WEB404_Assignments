import os
JWT_SECRET = os.environ.get("JWT_SECRET", "dev-secret-change-in-production")
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_SECONDS = 900
FLASK_SECRET = os.environ.get("SECRET_KEY", "flask-dev-key")
