NAMES_QUERY = '''MATCH (n) WHERE EXISTS(n.name) RETURN DISTINCT n.name AS name ORDER BY name'''
BSSID_QUERY = '''MATCH (n) WHERE EXISTS(n.bssid) RETURN DISTINCT n.bssid AS bssid ORDER BY bssid'''
OUI_QUERY = '''MATCH (n) WHERE EXISTS(n.oui) RETURN DISTINCT n.oui AS oui ORDER BY oui'''
TYPE_QUERY = '''MATCH (n) WITH DISTINCT labels(n) AS types UNWIND types AS type RETURN DISTINCT type ORDER BY type'''
AUTH_QUERY = '''MATCH (n) WHERE EXISTS(n.auth) RETURN DISTINCT n.auth AS auth ORDER BY auth'''
CIPHER_QUERY = '''MATCH (n) WHERE EXISTS(n.cipher) RETURN DISTINCT n.cipher AS cipher ORDER BY cipher'''
CHANNEL_QUERY = '''MATCH (n) WHERE EXISTS(n.channel) RETURN DISTINCT n.channel AS channel ORDER BY channel'''
SPEED_QUERY = '''MATCH (n) WHERE EXISTS(n.speed) RETURN DISTINCT n.speed AS speed ORDER BY speed'''
LANIP_QUERY = '''MATCH (n) WHERE EXISTS(n.lan) RETURN DISTINCT n.lan AS lan ORDER BY lan'''
DELETEDB_QUERY = '''MATCH (n) DETACH DELETE n'''

CONSTRAINT_QUERIES=[
        '''CREATE CONSTRAINT ON (n:Client) ASSERT n.bssid IS UNIQUE''',
        '''CREATE CONSTRAINT ON (n:WPA2) ASSERT n.bssid IS UNIQUE''',
        '''CREATE CONSTRAINT ON (n:WPA) ASSERT n.bssid IS UNIQUE''',
        '''CREATE CONSTRAINT ON (n:WEP) ASSERT n.bssid IS UNIQUE''',
        '''CREATE CONSTRAINT ON (n:Open) ASSERT n.bssid IS UNIQUE''',
        '''CREATE CONSTRAINT ON (n:AP) ASSERT n.name IS UNIQUE''',
        '''CREATE CONSTRAINT ON (n:Device) ASSERT n.bssid IS UNIQUE'''
        ]
ALL = (r'''MATCH (a)-[r]->(b)
        WITH
        {
            id: toString(id(a)) + toString(id(b)),
            source: id(a),
            target: id(b),
            name: type(r)
        }
        AS edges,
        {
            id: toString(id(a)),
            name: a.name,
            type: labels(a),
            bssid: a.bssid,
            oui: a.oui,
            fts: a.fts,
            lts: a.lts,
            pwr: toString(a.pwr)
        }
        AS clients,
        {
            id: toString(id(b)),
            name: b.name,
            type: labels(b),
            oui: b.oui,
            bssid: b.bssid,
            channel: toString(b.channel),
            speed: toString(b.speed),
            auth: b.auth,
            cipher: b.cipher,
            lan: b.lan
        }
        AS aps
        RETURN {nodes: collect(distinct clients) + collect(distinct aps), edges: collect(distinct edges)}
        ''')

INITIAL = (r'''MATCH p=(a)-[r]->(b)
            WITH
            {
                id: toString(id(a)) + toString(id(b)),
                source: id(a),
                target: id(b),
                name: type(r)
            }
            AS edges,
            {
                id: id(a),
                name: a.name,
                type: labels(a),
                bssid: a.bssid,
                oui: a.oui,
                fts: a.fts,
                lts: a.lts,
                pwr: toString(a.pwr)
            }
            AS clients,
            {
                id: id(b),
                name: b.name,
                type: labels(b),
                oui: b.oui,
                bssid: b.bssid,
                channel: toString(b.channel),
                speed: toString(b.speed),
                auth: b.auth,
                cipher: b.cipher,
                lan: b.lan
            }
            AS aps
            RETURN {nodes: collect(distinct clients) + collect(distinct aps), edges: collect(distinct edges)} LIMIT 100
            ''')

def searchRelations(value, prop):
    return (f'''MATCH (a)-[r]->(b) WHERE a.{prop} IN {value} OR b.{prop} IN {value}
            WITH
            {{
                id: toString(id(a)) + toString(id(b)),
                source: id(a),
                target: id(b),
                name: type(r)
            }}
            AS edges,
            {{
                id: id(a),
                name: a.name,
                type: labels(a),
                bssid: a.bssid,
                oui: a.oui,
                fts: a.fts,
                lts: a.lts,
                pwr: toString(a.pwr)
            }}
            AS clients,
            {{
                id: id(b),
                name: b.name,
                type: labels(b),
                oui: b.oui,
                bssid: b.bssid,
                channel: toString(b.channel),
                speed: toString(b.speed),
                auth: b.auth,
                cipher: b.cipher,
                lan: b.lan
            }}
            AS aps
            RETURN {{nodes: collect(distinct clients) + collect(distinct aps), edges: collect(distinct edges)}}
            ''')

def searchNoRelations(value, prop):
    return (f'''MATCH (b) WHERE b.{prop} IN {value} AND NOT (b)--()
            WITH
            {{
                id: id(b),
                name: b.name,
                type: labels(b),
                oui: b.OUI,
                bssid: b.bssid,
                channel: toString(b.channel),
                speed: toString(b.speed),
                auth: b.auth,
                cipher: b.cipher,
                lan: b.lan
            }}
            AS aps
            RETURN {{nodes: collect(distinct aps) }}''')

def searchLabelRelations(value):
    return (f'''MATCH (a)-[r]->(b:{value})
            WITH
            {{
                id: toString(id(a)) + toString(id(b)),
                source: id(a),
                target: id(b),
                name: type(r)
            }}
            AS edges,
            {{
                id: id(a),
                name: a.name,
                type: labels(a),
                bssid: a.bssid,
                oui: a.oui,
                fts: a.fts,
                lts: a.lts,
                pwr: toString(a.pwr)
            }}
            AS clients,
            {{
                id: id(b),
                name: b.name,
                type: labels(b),
                oui: b.oui,
                bssid: b.bssid,
                channel: toString(b.channel),
                speed: toString(b.speed),
                auth: b.auth,
                cipher: b.cipher,
                lan: b.lan
            }}
            AS aps
            RETURN {{nodes: collect(distinct clients) + collect(distinct aps), edges: collect(distinct edges)}}
            ''')

def searchLabelNoRelations(value):
    return (f'''MATCH (b:{value}) WHERE NOT (b)--()
            WITH
            {{
                id: id(b),
                name: b.name,
                type: labels(b),
                oui: b.OUI,
                bssid: b.bssid,
                channel: toString(b.channel),
                speed: toString(b.speed),
                auth: b.auth,
                cipher: b.cipher,
                lan: b.lan
            }}
            AS aps
            RETURN {{nodes: collect(distinct aps) }}''')

