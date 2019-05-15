import base64
import io
import json
import pandas as pd
import logging

logging.basicConfig(format='%(asctime)s - %(message)s')
macFrame = pd.DataFrame([json.loads(line) for line in open("macaddress.io-db.json").readlines()])

def parseUpload(content):
    content_type, content_string = content.split(',')
    decoded = base64.b64decode(content_string)
    if decoded.startswith(b'\r\nBSSID, First time seen, Last time seen, channel'):
        print("Airodump received!")
        bDict, sDict = __parseAirodump(decoded)
        return "Airodump", __makeAirodumpNodes(bDict, sDict)
    
    return ""

def macLookup(bssid):
    for x in range(16, 7, -1):
        if bssid[x] == ":":
            pass

        m = macFrame.loc[macFrame['oui'] == bssid[:x]]
        if not m.empty:
            return m['companyName'].values[0]

    return ""

def __cleanup(data, station=False):
    # Airodump format is dirty. Clean up for proper parsing.
    cleanList = []
    lines = data.split("\n")
    headers = list(map(str.strip, lines[0].split(",")))

    cleanList.append(",".join(headers))

    for line in lines[1:]:
        items = list(map(str.strip, line.split(",")))

        # Airodump uses commas in strings in CSV. Replace "," for list of items with |
        if station:
            essids = "|" + ",".join(items[6:]) + "|"
            newList = [item for item in items if item not in items[6:]]
            newList.append(essids)
            cleanList.append(",".join(newList))
        else:
            cleanList.append(",".join(items))

    return "\n".join(cleanList)

def __parseAirodump(decoded):

    bssidData, stationData, _ = decoded.split(b"\r\n\r\n")

    # Clean up AP table
    print("Cleaning BSSID data!")
    bssidData = __cleanup(bssidData.decode())
    bssidDF = pd.read_csv(io.StringIO(bssidData), header=0)

    # Clean up client tables
    print("Cleaning station data!")
    stationData = __cleanup(stationData.decode(), station=True)
    stationDF = pd.read_csv(io.StringIO(stationData), quotechar="|", header=0)

    # Change N/A to empty strings. Create dictionaries.
    bssidDF.fillna("", inplace=True)
    stationDF.fillna("", inplace=True)
    bDict = bssidDF.to_dict(orient='records')
    sDict = stationDF.to_dict(orient='records')
    return bDict, sDict

def __makeAirodumpNodes(bDict, sDict):
    bssidNodes, stationNodes = [], []

    print("Making BSSID nodes!")
    for entry in bDict:
        bssid = entry['BSSID']
        essid = entry['ESSID']
        speed = entry['Speed']
        channel = entry['channel']
        auth = entry['Authentication']
        cipher = entry['Cipher']
        lan = entry["LAN IP"].replace(" ", "")
        priv = entry["Privacy"]

        if lan == "0.0.0.0":
            lan = ""

        if  len(essid) == 0:
            essid = bssid
        
        oui = macLookup(bssid)
        
        if "WPA2" in priv:
            bNode = {'type': "WPA2", 'name': essid, 'bssid':bssid, 'oui':oui, 'encryption':"WPA2", 'speed':speed, 'channel':channel, 'auth':auth, 'cipher':cipher, 'lan':lan}
        elif "WPA" in priv:
            bNode = {'type': "WPA", 'name':essid, 'bssid':bssid, 'oui':oui, 'encryption':"WPA", 'speed':speed, 'channel':channel, 'auth':auth, 'cipher':cipher, 'lan':lan}
        elif "WEP" in priv:
            bNode = {'type':"WEP", 'name':essid, 'bssid':bssid, 'oui':oui, 'encryption':"WEP", 'speed':speed, 'channel':channel, 'auth':auth, 'cipher':cipher, 'lan':lan}
        elif "OPN" in priv:
            bNode = {'type': "Open", 'name':essid, 'bssid':bssid, 'oui':oui, 'encryption':"None", 'speed':speed, 'channel':channel, 'auth':auth, 'cipher':cipher, 'lan':lan}
        else:
            bNode = {'type': "AP", 'name':essid, 'bssid':bssid, 'oui':oui, 'encryption':"None", 'speed':speed, 'channel':channel, 'auth':auth, 'cipher':cipher, 'lan':lan}

        bssidNodes.append(bNode)

    #Parse list of clients and add probe relations
    print("Making station nodes!")
    for entry in sDict:
        essids = entry['Probed ESSIDs'].split(",")
        station = entry['Station MAC']
        fts = entry['First time seen']
        lts = entry['Last time seen']
        pwr = entry['Power']
        pkts = entry['# packets']
        if entry['BSSID'] != "(not associated)":
            bssid = entry['BSSID']
        else:
            bssid = None

        oui = macLookup(station)
        sNode = {'type': "Client", 'name': station, 'bssid': station, 'fts': fts, 'lts': lts, 'pwr': pwr, 'pkts': pkts, 'assoc': bssid, 'oui': oui}
        
        stationNodes.append([essids, sNode])

    return bssidNodes, stationNodes

'''for essid in essids:
    if any(node["name"] == essid for node in bssidNodes):
        break

    if len(essid) > 0:
        if existing is not None:
            e = existing
        else:
            e = Node("AP", name=essid)
        se = Relationship(s, "Probes", e)
        graph.create(se)

# AP Additions per Client
if bssid is not None:
    # If AP already exists by name, use existing node. Else create new.
    b = None
    for label in ["AP", "Open", "WEP", "WPA", "WPA2"]:
        existing = graph.nodes.match(label, bssid=bssid).first()
        if existing is not None:
            b = existing
            break
        else:
            b = Node("AP", bssid=bssid)

    probeSb = Relationship(s, "Probes", b)
    sb = Relationship(s, "AssociatedTo", b)
    graph.create(sb)'''