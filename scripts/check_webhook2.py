import sys, os, json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ["GUMROAD_ACCESS_TOKEN"] = "CQhSANYK0bHtZIJwpIocWlSx7zWE807NU6dlWp4y_MU"

from dotenv import load_dotenv
load_dotenv()
from src.db import get_connection

conn = get_connection()

# Check webhook_events raw payload
try:
    rows = conn.execute("SELECT event_type, payload, raw_body FROM webhook_events ORDER BY id DESC LIMIT 3").fetchall()
    for r in rows:
        print(f"Event: {r[0]}")
        print(f"  Payload: {r[1]}")
        try:
            p = json.loads(r[1])
            print(f"  custom: {p.get('custom', 'NOT FOUND')}")
            print(f"  email: {p.get('email', 'NOT FOUND')}")
            print(f"  id: {p.get('id', p.get('sale_id', 'NOT FOUND'))}")
        except:
            print(f"  Raw: {r[2][:200] if r[2] else 'empty'}")
        print()
except Exception as e:
    print(f"Error: {e}")

conn.close()
