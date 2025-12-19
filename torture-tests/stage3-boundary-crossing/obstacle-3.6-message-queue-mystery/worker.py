"""
Obstacle 3.6 consumer: delayed worker trusts queue contents and builds SQL inline.
Intentionally vulnerable sink for Code Scalpel to catch; do not parameterize in this fixture.
"""
import json
import psycopg2
from kafka import KafkaConsumer

consumer = KafkaConsumer('comments', bootstrap_servers=['kafka:9092'])
conn = psycopg2.connect("dbname=demo user=demo password=demo")


def handle_message(message):
    payload = json.loads(message.value)
    comment = payload["comment"]
    user_id = payload["userId"]

    with conn.cursor() as cur:
        # The actual injection risk is the user_id interpolated inside single quotes (no validation or bind params).
        cur.execute(f"INSERT INTO comments(user_id, body) VALUES ('{user_id}', $$ {comment} $$)")
        conn.commit()


for msg in consumer:
    try:
        handle_message(msg)
    except Exception as exc:
        # Minimal handling to keep the intentionally vulnerable worker alive for analysis.
        print(f"worker error: {exc}")
