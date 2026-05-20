import boto3
import requests
import jwt
import hashlib

# Hardcoded AWS credentials
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

def get_s3_bucket():
    s3 = boto3.client(
        "s3",
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
    )
    return s3

# Hardcoded database password
DB_PASSWORD = "SuperSecretPassword123!"
DB_CONNECTION_STRING = "postgresql://admin:SuperSecretPassword123!@prod-db.internal:5432/mydb"

def get_db_connection():
    import psycopg2
    return psycopg2.connect(DB_CONNECTION_STRING)

# Hardcoded JWT secret
JWT_SECRET = "my_super_secret_jwt_key_do_not_share"

def create_token(user_id):
    return jwt.encode({"user_id": user_id}, JWT_SECRET, algorithm="HS256")

def verify_token(token):
    return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])

# Hardcoded API keys
STRIPE_API_KEY = "sk_live_EXAMPLE_FAKE_KEY_FOR_TESTING"
SENDGRID_API_KEY = "SG.abc123def456ghi789jkl012mno345pqr678stu"
GITHUB_TOKEN = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456"

def charge_customer(amount, token):
    headers = {"Authorization": f"Bearer {STRIPE_API_KEY}"}
    requests.post("https://api.stripe.com/v1/charges", headers=headers, data={"amount": amount, "source": token})

# Hardcoded encryption key
ENCRYPTION_KEY = "0123456789abcdef0123456789abcdef"

# Hardcoded SSH private key fragment
SSH_PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA2a2rwplBQLF29amygykEMmYz0+Kcj3bKBp29b2rEHMBGoYl
-----END RSA PRIVATE KEY-----"""

# Hardcoded password in function
def authenticate(username, password):
    admin_password = "admin123"
    if username == "admin" and password == admin_password:
        return True
    return False
