# BEACONGRAPH (v0.1)

<p align='center'><img src='https://raw.githubusercontent.com/daddycocoaman/BeaconGraph/master/static/images/logo400.png' alt='logo'/></p>

## Description
BeaconGraph is an interactive tool that visualizes client and Access Point relationships. Inspired by [airgraph-ng](https://github.com/aircrack-ng/aircrack-ng/tree/master/scripts/airgraph-ng) and [Bloodhound](https://github.com/BloodHoundAD/BloodHound), BeaconGraph aims to support wireless security auditing. It is written in Python with GUI support by [pywebview](https://github.com/r0x0r/pywebview) and a [Neo4j](https://github.com/neo4j/neo4j) backend.

## Prerequisites

- Python3
- Neo4j

## Installation

**Supported Platforms:** 
- Ubuntu 18.04.1
- Linux Mint 19


### Linux
**NOTE**: Ensure your pip is for python3.
```
sudo apt-get install python3-pip python3-gi python-gi libwebkit2gtk-4.0-dev
pip3 install -r requirements.txt
pip3 install pywebview[qt5]  
```
There are some known bugs prevent Pywebview from launching on some Debian-based platforms at the moment. However, BeaconGraph can still be accessed by pointing your browser to `http://localhost:58008`.

## Acceptable CSV Formats
- airodump-ng

## Usage

```
./beaconGraph.py <airodump CSV file>
```

`--no-flush`: Do NOT delete current database before adding new entries<br>
`--manuf`: Update the Wireshark OUI Lookup file

**NOTE**: The larger the neo4j database, the more time it'll take to process. During testing, some large databases (over 2000 clients and access points combined) took over 10 minutes to render on screen.

## Screenshots
![Logo](examples/ui.png "BeaconGraph UI")
![Highlight](examples/csv1highlight.png "Highlights")


## Things To Do
- Verify all encryption types display properly (WEP/WPA)
- Clean up and separate code from one file
- Create wiki
- Package binaries for Windows/Linux/OSX
- Add Kismet CSV support

## License
This project is 100% open source. Use this code as you wish (except commercially) but please attribute to author and respect all licenses of third-party code. 

