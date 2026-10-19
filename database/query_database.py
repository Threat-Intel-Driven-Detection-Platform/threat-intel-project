import sqlite3, sys, os
DB=os.path.join('data','database','threat_intel.db')
if len(sys.argv)<2:
    print('Usage: python database\\query_database.py <IOC>'); raise SystemExit(1)
ioc=sys.argv[1]
con=sqlite3.connect(DB)
rows=con.execute('''SELECT i.value,i.canonical_type,s.name,o.threat_type,o.malware,o.confidence,o.status,o.event_info,o.first_seen,o.last_seen
FROM iocs i JOIN observations o ON o.ioc_id=i.ioc_id JOIN sources s ON s.source_id=o.source_id
WHERE i.value=? ORDER BY s.name''',(ioc,)).fetchall()
if not rows: print('IOC not found')
else:
    for r in rows: print(' | '.join('' if x is None else str(x) for x in r))
con.close()
