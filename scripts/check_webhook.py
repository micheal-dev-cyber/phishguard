import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ["GUMROAD_ACCESS_TOKEN"] = "CQhSANYK0bHtZIJwpIocWlSx7zWE807NU6dlWp4y_MU"

from dotenv import load_dotenv
load_dotenv()
from src.db import get_connection

conn = get_connection()

# Check webhook_events
try:
    rows = conn.execute("SELECT * FROM webhook_events ORDER BY id DESC LIMIT 5").fetchall()
    for r in rows:
        print(f"Event #{r[0]}: type={r[1]}, processed={r[4]}")
except Exception as e:
    print(f"No webhook_events table: {e}")

# Check billing_subscriptions
try:
    rows = conn.execute("SELECT * FROM billing_subscriptions").fetchall()
    for r in rows:
        print(f"Sub: user={r[1]}, plan={r[2]}, status={r[3]}")
except Exception as e:
    print(f"No billing_subscriptions table: {e}")

# Check tenants for micheal
try:
    rows = conn.execute("SELECT username, plan FROM tenants WHERE email='micheals.digital@gmail.com'").fetchall()
    for r in rows:
        print(f"Tenant: user={r[0]}, plan={r[1]}")
except Exception as e:
    print(f"No tenants query: {e}")

conn.close()
