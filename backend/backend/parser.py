import io
import json
import os
from pathlib import Path

import pandas as pd
from loguru import logger

from .db import Neo4j
from .labels import *

MAC_DB = pd.DataFrame(
    [
        json.loads(line)
        for line in open(Path(__file__).parent / "macaddress.io-db.json", "rb")
        .read()
        .splitlines()
    ]
)


def macLookup(bssid):
    for x in range(16, 7, -1):
        if bssid[x] == ":":
            pass

        m = MAC_DB.loc[MAC_DB["oui"] == bssid[:x]]
        if not m.empty:
            return m["companyName"].values[0]
    return


class AirodumpProcessor:
    def __init__(self) -> None:
        self.neo = None

    async def _cleanup(self, data, station=False):
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

    async def _parseAirodump(self, decoded):

        bssidData, stationData, _ = decoded.split(b"\r\n\r\n")

        # Clean up AP table
        logger.info("Cleaning BSSID data!")
        bssidData = await self._cleanup(bssidData.decode())
        bssidDF = pd.read_csv(io.StringIO(bssidData), header=0)

        # Clean up client tables
        logger.info("Cleaning station data!")
        stationData = await self._cleanup(stationData.decode(), station=True)
        stationDF = pd.read_csv(io.StringIO(stationData), quotechar="|", header=0)

        # Change N/A to empty strings. Create dictionaries.
        bssidDF.fillna("", inplace=True)
        stationDF.fillna("", inplace=True)
        bDict = bssidDF.to_dict(orient="records")
        sDict = stationDF.to_dict(orient="records")
        return (bDict, sDict)

    async def _insertAirodumpNodes(self, bDict, sDict):
        bssidNodes, stationNodes = [], []

        logger.info("Inserting BSSID nodes!")
        for entry in bDict:
            bssid = entry["BSSID"]
            essid = entry["ESSID"]
            speed = entry["Speed"]
            channel = entry["channel"]
            auth = entry["Authentication"]
            cipher = entry["Cipher"]
            lan = entry["LAN IP"].replace(" ", "")
            priv = entry["Privacy"]

            if lan == "0.0.0.0":
                lan = ""

            if len(essid) == 0:
                essid = bssid

            oui = macLookup(bssid)

            if "WPA2" in priv:
                bNode = {
                    "Type": "WPA2",
                    "Name": essid,
                    "BSSID": bssid,
                    "OUI": oui,
                    "Encryption": "WPA2",
                    "Speed": speed,
                    "Channel": channel,
                    "Auth": auth,
                    "Cipher": cipher,
                    "LAN": lan,
                }
            elif "WPA" in priv:
                bNode = {
                    "Type": "WPA",
                    "Name": essid,
                    "BSSID": bssid,
                    "OUI": oui,
                    "Encryption": "WPA",
                    "Speed": speed,
                    "Channel": channel,
                    "Auth": auth,
                    "Cipher": cipher,
                    "LAN": lan,
                }
            elif "WEP" in priv:
                bNode = {
                    "Type": "WEP",
                    "Name": essid,
                    "BSSID": bssid,
                    "OUI": oui,
                    "Encryption": "WEP",
                    "Speed": speed,
                    "Channel": channel,
                    "Auth": auth,
                    "Cipher": cipher,
                    "LAN": lan,
                }
            elif "OPN" in priv:
                bNode = {
                    "Type": "Open",
                    "Name": essid,
                    "BSSID": bssid,
                    "OUI": oui,
                    "Encryption": "Open",
                    "Speed": speed,
                    "Channel": channel,
                    "Auth": auth,
                    "Cipher": cipher,
                    "LAN": lan,
                }
            else:
                bNode = {
                    "Type": "AP",
                    "Name": essid,
                    "BSSID": bssid,
                    "OUI": oui,
                    "Encryption": "None",
                    "Speed": speed,
                    "Channel": channel,
                    "Auth": auth,
                    "Cipher": cipher,
                    "LAN": lan,
                }

            self.neo.insert_asset(bNode, bNode["Type"], bNode["BSSID"], ["Device"])

        # Parse list of clients and add probe relations
        logger.info("Inserting station nodes!")
        for entry in sDict:
            essids = entry["Probed ESSIDs"].split(",")
            station = entry["Station MAC"]
            fts = entry["First time seen"]
            lts = entry["Last time seen"]
            pwr = entry["Power"]
            pkts = entry["# packets"]
            if entry["BSSID"] != "(not associated)":
                bssid = entry["BSSID"]
            else:
                bssid = None

            oui = macLookup(station)
            sNode = {
                "Type": "Client",
                "Name": station,
                "FirstTimeSeen": fts,
                "LastTimeSeen": lts,
                "Power": pwr,
                "Packets": pkts,
                "OUI": oui,
            }

            self.neo.insert_asset(sNode, "Client", sNode["Name"], ["Device"])

            if bssid:
                self.neo.create_relationship(
                    sNode["Name"], "Client", bssid, "Device", ASSOCIATED
                )

            for essid in essids:
                if essid:
                    self.neo.create_relationship(
                        sNode["Name"], "Client", essid, "Device", PROBES
                    )

    async def parseUpload(self, content: bytes):
        if b"BSSID, First time seen, Last time seen, channel" in content:
            logger.info("Airodump received!")
            bDict, sDict = await self._parseAirodump(content)
            await self._insertAirodumpNodes(bDict, sDict)
        else:
            logger.error("Not an Airodump file!")

    async def process(self, upload: bytes, filename: str, neo_user: str, neo_pass: str):

        server = (
            "bolt://beacongraph-neo4j:7687"
            if os.environ.get("DOCKER_BEACONGRAPH")
            else "bolt://localhost:7687"
        )
        # TODO: Pass whole neo4j params from frontend or use .env for server
        self.neo = Neo4j(server=server, user=neo_user, password=neo_pass)
        await self.parseUpload(upload)
        self.neo.query(
            "MATCH (n) WHERE n.Name IS NULL SET n.Name = n.id SET n.Type = 'AP'"
        )
        logger.info(f"Completed ingestion of {filename}")
