import psycopg2
import os
import urllib.parse as up

def get_connection():
    up.uses_netloc.append("postgres")
    url = os.environ["DATABASE_URL"]
    return psycopg2.connect(url)
