import json, sqlite3, sys, os, re
from datetime import datetime, timezone

DB_PATH = os.path.join('data','database','threat_intel.db')
DEFAULT_JSON = os.path.join('data','database','global_iocs.json')
SOURCE_META = {
 'circl':('CIRCL OSINT','feed','https://www.circl.lu/doc/misp/feed-osint/'),
 'feodo':('Feodo Tracker','feed','https://feodotracker.abuse.ch/'),
 'infoblox':('Infoblox Threat Intelligence','repository','https://github.com/Infoblox-CTO/threat-intelligence'),
 'malwarebazaar':('MalwareBazaar','api','https://bazaar.abuse.ch/'),
 'meta':('Meta Threat Research','repository','https://github.com/facebook/threat-research'),
 'openphish':('OpenPhish','feed','https://openphish.com/'),
 'otx':('AlienVault OTX','api','https://otx.alienvault.com/'),
 'talos':('Cisco Talos','repository','https://github.com/Cisco-Talos/IOCs'),
 'threatfox':('ThreatFox','api','https://threatfox.abuse.ch/'),
 'urlhaus':('URLhaus','api','https://urlhaus.abuse.ch/'),
}

def jdump(x): return json.dumps(x, ensure_ascii=False, separators=(',',':')) if x is not None else None

def scalar(x):
    if x is None: return None
    if isinstance(x,(dict,list)): return jdump(x)
    return str(x)

def source_key(name):
    s=(name or '').strip().lower()
    aliases={'circl':'circl','circl osint':'circl','cisco talos':'talos','talos':'talos','alienvault otx':'otx','otx':'otx','urlhaus':'urlhaus','threatfox':'threatfox','feodo tracker':'feodo','feodo':'feodo','malwarebazaar':'malwarebazaar','openphish':'openphish','infoblox':'infoblox','meta threat research':'meta','meta':'meta'}
    return aliases.get(s,s)

def detect_array_key(path):
    with open(path,'rb') as f:
        depth=0; key=None
        dec=json.JSONDecoder(); buf=''
        while True:
            chunk=f.read(1024*1024)
            if not chunk: break
            buf += chunk.decode('utf-8')
            if depth==0:
                m=re.search(r'"([^"]+)"\s*:\s*\[',buf)
                if m: return m.group(1)
            if len(buf)>5*1024*1024: buf=buf[-1024:]
    return None

def insert_source(cur, key):
    key=source_key(key); meta=SOURCE_META.get(key)
    if meta:
        name,typ,url=meta
    else:
        name=key or 'unknown'; typ='unknown'; url=None
    cur.execute('INSERT OR IGNORE INTO sources(name,source_type,url,description) VALUES(?,?,?,?)',(name,typ,url,'Imported source'))
    cur.execute('SELECT source_id FROM sources WHERE name=?',(name,))
    return cur.fetchone()[0]

def ensure_tag(cur, name):
    cur.execute('INSERT OR IGNORE INTO tags(name) VALUES(?)',(str(name),)); cur.execute('SELECT tag_id FROM tags WHERE name=?',(str(name),)); return cur.fetchone()[0]
def ensure_malware(cur, name):
    cur.execute('INSERT OR IGNORE INTO malware(name) VALUES(?)',(str(name),)); cur.execute('SELECT malware_id FROM malware WHERE name=?',(str(name),)); return cur.fetchone()[0]

def build(json_path=DEFAULT_JSON):
    if not os.path.exists(json_path): raise FileNotFoundError(json_path)
    os.makedirs(os.path.dirname(DB_PATH),exist_ok=True)
    if os.path.exists(DB_PATH): os.remove(DB_PATH)
    conn=sqlite3.connect(DB_PATH); cur=conn.cursor()
    with open(os.path.join(os.path.dirname(__file__),'schema.sql'),encoding='utf-8') as f: conn.executescript(f.read())
    conn.execute('PRAGMA foreign_keys=ON'); conn.execute('PRAGMA journal_mode=WAL'); conn.execute('PRAGMA synchronous=NORMAL')
    array_key=detect_array_key(json_path)
    if not array_key: raise RuntimeError('Could not find top-level IOC array (expected iocs).')
    # Full JSON load is intentional here because the existing global file is already a consolidated dataset.
    with open(json_path,encoding='utf-8') as f: doc=json.load(f)
    items=doc.get(array_key,[]) if isinstance(doc,dict) else doc
    total=len(items); print(f'IOC records found: {total:,}')
    source_cache={}; obs_count=0
    for n,obj in enumerate(items,1):
        value=obj.get('value'); typ=obj.get('canonical_type') or obj.get('type')
        if not value or not typ: continue
        cur.execute('INSERT OR IGNORE INTO iocs(value,canonical_type) VALUES(?,?)',(str(value),str(typ)))
        cur.execute('SELECT ioc_id FROM iocs WHERE value=? AND canonical_type=?',(str(value),str(typ)))
        ioc_id=cur.fetchone()[0]
        srcs=obj.get('sources') or []
        records=obj.get('records') or []
        for rec in records:
            sk=source_key(rec.get('source') or (srcs[0] if len(srcs)==1 else 'unknown'))
            if sk not in source_cache: source_cache[sk]=insert_source(cur,sk)
            sid=source_cache[sk]
            fs=rec.get('first_seen'); ls=rec.get('last_seen')
            cur.execute('INSERT INTO observations(ioc_id,source_id,source_record_id,event_id,event_uuid,event_info,first_seen,last_seen,timestamp,to_ids,category,comment,threat_type,malware,confidence,reporter,status,reference,tlp,raw_metadata) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',(
                ioc_id,sid,rec.get('source_record_id'),rec.get('event_id'),rec.get('event_uuid'),rec.get('event_info'),fs,ls,scalar(rec.get('timestamp')),
                int(rec['to_ids']) if isinstance(rec.get('to_ids'),bool) else None,rec.get('category'),rec.get('comment'),rec.get('threat_type'),scalar(rec.get('malware')),scalar(rec.get('confidence')),rec.get('reporter'),rec.get('status'),rec.get('reference'),rec.get('tlp'),jdump(rec)))
            oid=cur.lastrowid; obs_count+=1
            for tag in (rec.get('tags') or []):
                tid=ensure_tag(cur,tag); cur.execute('INSERT OR IGNORE INTO observation_tags VALUES(?,?,?)',(oid,tid,'record'))
            for tag in (rec.get('event_tags') or []):
                tid=ensure_tag(cur,tag); cur.execute('INSERT OR IGNORE INTO observation_tags VALUES(?,?,?)',(oid,tid,'event'))
            mal=rec.get('malware')
            if isinstance(mal,str) and mal.strip():
                mid=ensure_malware(cur,mal.strip()); cur.execute('INSERT OR IGNORE INTO observation_malware VALUES(?,?)',(oid,mid))
            for tech in (rec.get('mitre_techniques') or rec.get('attack_ids') or []):
                if isinstance(tech,dict): tid=tech.get('id') or tech.get('technique_id'); name=tech.get('name')
                else: tid=str(tech); name=None
                if tid:
                    cur.execute('INSERT OR IGNORE INTO mitre_techniques(technique_id,name) VALUES(?,?)',(tid,name)); cur.execute('INSERT OR IGNORE INTO observation_mitre VALUES(?,?)',(oid,tid))
            refs=rec.get('references') or []
            if isinstance(refs,str): refs=[refs]
            for ref in refs:
                if isinstance(ref,dict): ref=ref.get('url') or ref.get('reference')
                if ref:
                    cur.execute('INSERT OR IGNORE INTO ioc_references(url) VALUES(?)',(str(ref),)); cur.execute('SELECT reference_id FROM ioc_references WHERE url=?',(str(ref),)); rid=cur.fetchone()[0]; cur.execute('INSERT OR IGNORE INTO observation_references VALUES(?,?)',(oid,rid))
            if obs_count % 5000 == 0: conn.commit(); print(f'Processed {n:,}/{total:,} IOCs | observations {obs_count:,}')
        # Sources declared on IOC but absent from records still get a relationship.
        for s in srcs:
            sk=source_key(s)
            if sk not in source_cache: source_cache[sk]=insert_source(cur,sk)
            sid=source_cache[sk]
            cur.execute('INSERT OR IGNORE INTO ioc_sources(ioc_id,source_id) VALUES(?,?)',(ioc_id,sid))
        if n % 5000 == 0: conn.commit()
    cur.execute('''INSERT OR REPLACE INTO ioc_sources(ioc_id,source_id,first_seen,last_seen,record_count)
                   SELECT ioc_id,source_id,MIN(first_seen),MAX(last_seen),COUNT(*) FROM observations GROUP BY ioc_id,source_id''')
    conn.commit(); conn.execute('VACUUM'); conn.close()
    print(f'Created: {DB_PATH}')
    print(f'IOCs: {total:,} | observations: {obs_count:,}')

if __name__=='__main__':
    build(sys.argv[1] if len(sys.argv)>1 else DEFAULT_JSON)
