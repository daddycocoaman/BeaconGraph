# BEACONGRAPH (v1.0.0-beta)

![BeaconGraph logo](docs/logo.png)

## Description

BeaconGraph is an interactive tool that visualizes client and Access Point relationships. Inspired by [airgraph-ng](https://github.com/aircrack-ng/aircrack-ng/tree/master/scripts/airgraph-ng) and [Bloodhound](https://github.com/BloodHoundAD/BloodHound), BeaconGraph aims to support wireless security auditing. The frontend is written in Vue and the backend in Python 3.8. Data is parsed into a [Neo4j](https://github.com/neo4j/neo4j) database. The BeaconGraph CLI supports direct parsing of packet captures produced by airodump-ng into a target Neo4j or [ArcadeDB](https://arcadedb.com/) database.

## Installation

## With Docker

Most users may find it easier to install Beacongraph via Docker. This is the recommended method.

```bash
git clone https://github.com/daddycocoaman/BeaconGraph
docker-compose up
```

The `docker-compose` file will create three containers:

- Frontend
- Backend
- Neo4j v4

By default, the BeaconGraph container will expose the UI on port 9091. The neo4j container will expose neo4j on ports 7474 (HTTP), and 7687 (Bolt). You may initially interact directly with the neo4j interface on port 7474.

**Note**: Currently, BeaconGraph only supports running these containers locally. Attempting to upload to the frontend hosted remotely will be unsuccessful but this behavior is expected to change in the future.

The default credentials for neo4j are: **neo4j/password**. You can change this in the `docker-compose` file via the NEO4JAUTH environment variable.

## Command line ingestion

The CLI writes data straight into a graph (neo4j/arcadedb) database, skipping the web upload and letting you bring your own UI:

```bash
# Install the CLI with pipx
git clone github.com/daddycocoaman/BeaconGraph && pipx install ./BeaconGraph
# Parsing a PCAP into the `mydatabase` DB in ArcadeDB
beacongraph-cli arcadedb capture-01.cap --database mydatabase
# Parsing a second PCAP into the DB; --merge required since data is already present
beacongraph-cli arcadedb another-capture.cap --database mydatabase --merge
# Exporting PCAP info into the CSV format
beacongraph-cli export capture-01.cap -o out.csv
# Neo4j export example
beacongraph-csv neo4j capture-01.cap
```

Both accept `--uri`, `-u/--username`, `-p/--password` and `--log-level`. For ArcadeDB export, the default database name is `beacongraph`.

### CSV vs PCAP Parsing

Airodump produces a CSV with its own fifteen-column summary. Reading the packket capture directly can identify additional infomration:

- **WPA3.** The CSV classifier tests `"WPA2" in privacy` then `"WPA" in privacy`, and `"WPA3"` contains `"WPA"` - so a WPA3 network can only ever be reported as WPA. Parsing the RSN element reads the AKM suites directly.
- **802.11r and management frame protection.** `MGT` in the CSV is 802.1X *and* FT-802.1X flattened together; the `akm` property keeps them apart, and `pmf` records whether protected management frames are disabled, capable or required.
- **Handshakes.** EAPOL messages are tracked per client-AP pair, so an `Associated` edge can say how much of a 4-way handshake was captured, whether it is enough to attack, and whether a PMKID was recovered.
- **RADIUS server certificate chains.** On an 802.1X network the authentication server presents its whole X.509 chain before the tunnel closes, so a capture of the first frames of any enterprise association carries the internal PKI - the server identity a client is configured to trust, and every CA vouching for it. This can be interesting to determine seperate wireless networks sharing an authenication backbone.
- **Deauthentication activity**, with reason codes.
- **Band and PHY generation** - 2.4/5/6 GHz and 802.11b/g/a/n/ac/ax.

What the capture *cannot* supply, it omits rather than inventing. A capture without a radiotap header carries no signal strength at all, so `power` is simply absent. Ingesting the matching CSV afterwards fills those values in without duplicating anything, because every write is a MERGE that only sets the keys it has.

## Usage

Once logged in, you are able to upload data using the "Upload Data" widget. Currently only `airodump-ng` output is supported. After the data is ingested, you can query the database using [Cypher](https://neo4j.com/developer/cypher/intro-cypher/) language. Example queries are available in the Queries tab.

To remove previously ingested data from the UI, use the `Clear Ingested Data` button in the `Database` tab. If you want to remove Neo4j data at the container level, `docker compose down -v` will also clear the database volume created by Docker.

## Cypher Quick Start

BeaconGraph uses Neo4j's Cypher query language. A simple way to teach it is to think in three steps:

1. `MATCH` a graph pattern.
2. Optionally use `WHERE` to filter labels or properties.
3. `RETURN` the nodes or relationships you want drawn.

Useful patterns:

- `MATCH (n) RETURN n LIMIT 25`
- `MATCH (n:Open) RETURN n`
- `MATCH (c:Client)-[r:Probes]->(d:Device) RETURN c, r, d`
- `MATCH (c:Client)-[r]->(d:Device) RETURN c, r, d`
- `MATCH (n) WHERE n.Name CONTAINS "wifi" RETURN n LIMIT 50`
- `MATCH (a) WHERE NOT (a)-[:Probes|Associated]->() RETURN a`

The `Queries` tab in the UI now includes a short primer plus worked examples that students can copy into the `Raw Query` panel and modify.

## Screenshots

![Logo](docs/screenshot1.png "BeaconGraph UI")

## Bugs

- You may recieve an error or "no results found" if you try to query before an upload of data has finished processing. This should disappear once the ingestion is complete.
