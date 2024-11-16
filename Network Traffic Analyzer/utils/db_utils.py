import sqlite3
from datetime import datetime

# Store packets in SQLite DB
def store_packet_in_db(packet):
    try:
        conn = sqlite3.connect('network_traffic.db')
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS packets (id INTEGER PRIMARY KEY, timestamp TEXT, summary TEXT)''')
        c.execute("INSERT INTO packets (timestamp, summary) VALUES (?, ?)", (datetime.now(), str(packet.summary())))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error storing packet: {e}")