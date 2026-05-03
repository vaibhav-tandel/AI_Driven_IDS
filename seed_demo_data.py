# seed_demo_data.py — Seed the database with diverse demo data for dashboard testing
import sys, os, random
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from realtime.db import IDSDatabase
from realtime.alert_system import get_severity

db = IDSDatabase()
db.clear_all()

attacks = ['DDoS', 'PortScan', 'DoS Hulk', 'DoS GoldenEye', 'DoS Slowloris',
           'FTP-Patator', 'SSH-Patator', 'Bot', 'Web Attack', 'Heartbleed', 'Infiltration']

countries = [
    ('China', 'Beijing', 39.9, 116.4),
    ('Russia', 'Moscow', 55.75, 37.62),
    ('United States', 'Fremont', 37.55, -121.99),
    ('Germany', 'Berlin', 52.52, 13.41),
    ('Romania', 'Bucharest', 44.43, 26.1),
    ('Brazil', 'Sao Paulo', -23.55, -46.63),
    ('India', 'Mumbai', 19.08, 72.88),
    ('Japan', 'Tokyo', 35.68, 139.69),
    ('South Korea', 'Seoul', 37.57, 126.98),
    ('Netherlands', 'Amsterdam', 52.37, 4.90),
]

ext_ips = ['203.0.113.', '198.51.100.', '45.33.32.', '185.220.101.', '91.219.236.', '77.247.181.']

print("Seeding demo data...")

for i in range(500):
    is_attack = random.random() < 0.35
    if is_attack:
        at = random.choice(attacks)
        conf = random.uniform(65, 99)
        sev = get_severity(at, conf)
        geo = random.choice(countries)
        src = random.choice(ext_ips) + str(random.randint(1, 254))
    else:
        at = 'Benign'
        conf = random.uniform(85, 99)
        sev = 'LOW'
        geo = ('Local Network', 'Internal', None, None)
        src = '192.168.1.' + str(random.randint(1, 254))

    minute = 30 + (i * 30) // 500
    second = random.randint(0, 59)
    ts = '2026-02-18 13:' + str(minute).zfill(2) + ':' + str(second).zfill(2)

    db.insert_alert({
        'timestamp': ts,
        'src_ip': src,
        'dst_ip': '192.168.1.' + str(random.randint(1, 10)),
        'src_port': random.randint(1024, 65535),
        'dst_port': random.choice([80, 443, 21, 22, 8080]),
        'protocol': random.choice(['TCP', 'UDP']),
        'attack_type': at,
        'confidence': conf,
        'severity': sev,
        'is_false_alarm': 0,
        'geo_country': geo[0],
        'geo_city': geo[1],
        'geo_lat': geo[2],
        'geo_lon': geo[3],
        'geo_isp': 'ISP',
        'flow_duration': random.uniform(0.1, 30),
        'total_packets': random.randint(5, 500),
        'total_bytes': random.randint(500, 100000),
    })

# Add traffic stats
for i in range(20):
    ts = '2026-02-18 13:' + str(30 + i).zfill(2) + ':00'
    db.insert_traffic_stat({
        'timestamp': ts,
        'total_flows': random.randint(20, 50),
        'normal_flows': random.randint(10, 35),
        'attack_flows': random.randint(5, 15),
        'false_alarms': random.randint(0, 3),
        'avg_confidence': random.uniform(75, 95),
    })

counts = db.get_alert_counts()
print("Total alerts:", counts["total"])
print("Attacks:", counts["attacks"])
print("Normal:", counts["normal"])
print("Attack types:", len(db.get_attack_distribution()))
print("Geo entries:", len(db.get_geo_data()))
print("Done!")
