from time import sleep
from py2neo import Graph, Node, Relationship
from py2neo.database import ClientError
from collections import Counter
import json
import base64
import pandas
import bg_presets
import configparser

config = configparser.ConfigParser()
config.read('settings.cfg')

class neoHandler:
    def __init__(self,uri,user, passwd):
        self.DB_URI = config['neo4j']['uri']
        self.DB_USER = config['neo4j']['User']
        self.DB_PASS = config['neo4j']['Password']
        self.WPA2_COLOR = config['legend']['WPA2']
        self.WPA_COLOR = config['legend']['WPA']
        self.WEP_COLOR = config['legend']['WEP']
        self.OPEN_COLOR = config['legend']['Open']
        self.AP_COLOR = config['legend']['AP']
        self.CLIENT_COLOR = config['legend']['Client']
        self.PROBE_COLOR = config['legend']['Probes']
        self.ASSOC_COLOR = config['legend']['AssociatedTo']
        
        self.graph = Graph(uri, auth=(user, passwd))
        self.user = user
        self.uri = self.graph.database.uri
        self.INITIAL = True
        
        for con in bg_presets.CONSTRAINT_QUERIES:
            self.graph.run(con)

        self.names = self.getNames()
        self.bssids = self.getBssids()
        self.ouis = self.getOUIs()
        self.types = self.getTypes()
        self.auths = self.getAuths()
        self.ciphers = self.getCiphers()
        self.channels = self.getChannels()
        self.speeds = self.getSpeeds()
        self.lanips = self.getLanIPs()

    
    def getNames(self):
        return list(map(lambda x: x['name'], self.graph.run(bg_presets.NAMES_QUERY).data()))

    def getBssids(self):
        return list(map(lambda x: x['bssid'], self.graph.run(bg_presets.BSSID_QUERY).data()))
    
    def getOUIs(self):
        return list(map(lambda x: x['oui'], self.graph.run(bg_presets.OUI_QUERY).data()))
    
    def getTypes(self):
        return list(map(lambda x: x['type'], self.graph.run(bg_presets.TYPE_QUERY).data()))
    
    def getAuths(self):
        return list(map(lambda x: x['auth'], self.graph.run(bg_presets.AUTH_QUERY).data()))
    
    def getCiphers(self):
        return list(map(lambda x: x['cipher'], self.graph.run(bg_presets.CIPHER_QUERY).data()))
    
    def getChannels(self):
        return list(map(lambda x: x['channel'], self.graph.run(bg_presets.CHANNEL_QUERY).data()))
    
    def getSpeeds(self):
        return list(map(lambda x: x['speed'], self.graph.run(bg_presets.SPEED_QUERY).data()))

    def getLanIPs(self):
        return list(map(lambda x: x['lan'], self.graph.run(bg_presets.LANIP_QUERY).data()))

    def getDbStats(self):
        c = Counter()
        nodeRes = self.graph.run('''MATCH (n) WITH DISTINCT labels(n) AS temp, COUNT(n) as tempCnt
                                UNWIND temp AS label
                                RETURN label, SUM(tempCnt) AS cnt''').data()
        probeCnt = self.graph.run('MATCH ()-[r:Probes]->() RETURN count(r) AS probes').data()[0].get('probes')
        assocCnt = self.graph.run('MATCH ()-[r:AssociatedTo]->() RETURN count(r) AS assoc').data()[0].get('assoc')
        
        for res in nodeRes:
            c.update({res['label']: res['cnt']})
        c.update({'Probes': probeCnt, 'Assoc': assocCnt})

        self.names = self.getNames()
        return c

    def dataToJSON(self, relationJSON):
        checkDupes, returnJson = {}, {}
        returnJson['nodes'] = []
        returnJson['edges'] = []

        for idx, node in enumerate(relationJSON['nodes']):
            node['type'] = node['type'][0]

            #Merge nodes that are both APs and Clients (mesh)
            if node['id'] not in checkDupes.values():
                checkDupes[idx] = node['id']
                returnJson['nodes'].append({"data": node, "selected": 'false', "group": "nodes"})
            else:
                inDupe = [key for (key, value) in checkDupes.items() if value == node['id']][0]
                if node['type'] == "Client":
                    node = {**node, **returnJson['nodes'][inDupe]['data']}
                else:
                    node = {**returnJson['nodes'][inDupe]['data'], **node}
                returnJson['nodes'][inDupe]['data'] = node
        
        for idx, edge in enumerate(relationJSON['edges']):
            returnJson['edges'].append({"data": edge, "selected": 'false', "group": "edges"})

        return returnJson

    def initialQuery(self):
        relations = self.graph.evaluate(bg_presets.INITIAL)
        self.INITIAL = False
        return self.dataToJSON(relations)

    def searchQuery(self, value, prop):
        if prop == "type":
            labelRelations = self.graph.evaluate(bg_presets.searchLabelRelations(value[0]))
            labelNoRelations = self.graph.evaluate(bg_presets.searchLabelNoRelations(value[0]))
            tempDict = {k:v + labelRelations[k] for k,v in labelNoRelations.items()}
            merged = {**labelRelations, **tempDict}
        else:
            relations = self.graph.evaluate(bg_presets.searchRelations(value, prop))
            noRelations = self.graph.evaluate(bg_presets.searchNoRelations(value, prop))
            tempDict = {k:v + relations[k] for k,v in noRelations.items()}
            merged = {**relations, **tempDict}

        return self.dataToJSON(merged)

    def handleIncomingData(self, dType, data):
        if dType == "Airodump":
            self.insertAiroData(data)
    
    def insertAiroData(self, data):
        print("Inserting node data!")
        bssidNodes, stationNodes = data[0][0], data[0][1]
        for b in bssidNodes:
            try:
                bNode = Node(b['type'], name=b['name'], bssid=b['bssid'], oui=b['oui'], encryption=b["encryption"], speed=b['speed'], channel=b['channel'], auth=b['auth'], cipher=b['cipher'], lan=b['lan'])
                bNode.add_label("Device")
                self.graph.create(bNode)
            except ClientError:
                pass
        
        for essids, s in stationNodes:
            sNode = self.graph.nodes.match("Device", bssid=s['bssid']).first()
            if sNode is None:
                sNode = Node(s["type"], name=s['name'], bssid=s['bssid'], FirstTimeSeen=s['fts'], LastTimeSeen=s['lts'],Power=s['pwr'], NumPackets=s['pkts'], Association=s['assoc'], oui=s['oui'])
                sNode.add_label("Device")
            else:
                sNode['FirstTimeSeen'] = s['fts']
                sNode['LastTimeSeen'] = s['lts']
                sNode['Power'] = s['pwr']
                sNode['NumPackets'] = s['pkts']
                sNode['Association'] =s['assoc']
                self.graph.push(sNode)
                sNode = self.graph.nodes.match("Device", bssid=s['bssid']).first()

            for essid in essids: 
                nExisting = self.graph.nodes.match("Device", name=essid).first()
                if len(essid) > 0:
                    newProbe = Node("AP", name=essid)
                    newProbe.add_label("Device")
                    self.graph.create(Relationship(sNode, "Probes", nExisting or newProbe))
            
            if s['assoc'] is not None:
                aExisting = self.graph.nodes.match("Device", bssid=s['assoc']).first()
                newAssoc = Node("AP", bssid=s['assoc'])
                newAssoc.add_label("Device")
                self.graph.create(Relationship(sNode, "AssociatedTo", aExisting or newAssoc))
        
        print("Database updated!")

    def deleteDB(self):
        self.graph.run(bg_presets.DELETEDB_QUERY)
