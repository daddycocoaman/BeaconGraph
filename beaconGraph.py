#!/usr/bin/env python
#v0.1.1

import argparse
import base64
import io
import os
import json
import threading
import webview
import webbrowser
import requests
import tkinter as tk
import pandas as pd
from tkinter import filedialog
from manuf import manuf
from time import sleep
from flask import Flask, render_template, request, jsonify, redirect, url_for
from flask_login import current_user, LoginManager, login_user, UserMixin
from py2neo import Graph, Node, Relationship


app = Flask(__name__)
app.secret_key = os.urandom(32)
log_manager = LoginManager(app)

FLUSH_DB = True
CSV_FILE = ""
MANUF_UPDATE = False
GUI = False

class User(UserMixin):
    def __init__(self, userId):
        self.id = userId


def cleanup(data, station=False):
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


def cpg(graph, stationDict, bssidDict):

    mac = manuf.MacParser(update=MANUF_UPDATE)
    for item in stationDict:
        essids = item['Probed ESSIDs'].split(",")
        station = item['Station MAC']
        fts = item['First time seen']
        lts = item['Last time seen']
        pwr = item['Power']
        pkts = item['# packets']
        if item['BSSID'] != "(not associated)":
            bssid = item['BSSID']
        else:
            bssid = None

            try:
                oui = mac.get_comment(station)
            except:
                oui = mac.get_manuf(station)

            if oui is None:
                oui = "Private"
        
        s = Node("Client", name=station, FirstTimeSeen=fts, LastTimeSeen=lts,Power=pwr, NumPackets=pkts, Association=bssid, OUI=oui)
        for essid in essids:
            existing = graph.nodes.match("AP", name=essid).first()

            if len(essid) > 0:
                if existing is not None:
                    e = existing
                else:
                    e = Node("AP", name=essid)
                se = Relationship(s, "Probes", e)
                graph.create(se)

        # AP Additions per Client
        if bssid is not None:
            ap = (i for i in bssidDict if i['BSSID'] == bssid)
            entry = next(ap)
            essid = entry['ESSID']
            speed = entry['Speed']
            channel = entry['channel']
            auth = entry['Authentication']
            cipher = entry['Cipher']
            lan = entry["LAN IP"].replace(" ", "")
            if lan == "0.0.0.0":
                lan = ""

            if len(essid) == 0:
                essid = bssid

            # Get the OUIs for APs, if available
            try:
                oui = mac.get_comment(bssid)
            except:
                oui = mac.get_manuf(bssid)
            if oui is None:
                oui = "Private"

            # If AP already exists by name, use existing node. Else create new.
            existing = graph.nodes.match("AP", name=essid).first()
            if existing is not None:
                b = existing
            else:
                priv = entry["Privacy"]
                if "WPA2" in priv:
                    b = Node("WPA2", name=essid, OUI=oui, Encryption="WPA2",
                             speed=speed, channel=channel, auth=auth, cipher=cipher, lan=lan)
                elif "WPA" in priv:
                    b = Node("WPA", name=essid, OUI=oui, Encryption="WPA",
                             speed=speed, channel=channel, auth=auth, cipher=cipher, lan=lan)
                elif "WEP" in priv:
                    b = Node("WEP", name=essid, OUI=oui, Encryption="WEP",
                             speed=speed, channel=channel, auth=auth, cipher=cipher, lan=lan)
                elif "OPN" in priv:
                    b = Node("Open", name=essid, OUI=oui, Encryption="None",
                             speed=speed, channel=channel, auth=auth, cipher=cipher, lan=lan)
                else:
                    b = Node("AP", name=essid, OUI=oui, Encryption="None",
                             speed=speed, channel=channel, auth=auth, cipher=cipher, lan=lan)

            probeSb = Relationship(s, "Probes", b)
            sb = Relationship(s, "AssociatedTo", b)
            graph.delete(probeSb)
            graph.create(sb)


def writeJson(graph):
    # Pull database and write to JSON
    dbfile = open("static/db.json", "w")
    query = graph.run('''MATCH (a)-[r]->(b)
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
        oui: a.OUI,
        fts: a.fts,
        lts: a.lts,
        pwr: toString(a.pwr)
    }
    AS clients,
    {
        id: id(b),
        name: b.name,
        type: labels(b),
        oui: b.OUI,
        channel: toString(b.channel),
        speed: toString(b.speed),
        auth: b.auth,
        cipher: b.cipher,
        lan: b.lan
    }
    AS aps
    RETURN {nodes: collect(distinct clients) + collect(distinct aps), edges: collect(distinct edges)}
    ''').data()

    # Settings for different node types
    graphJSON = {}
    graphJSON = query[0].pop(
        "{nodes: collect(distinct clients) + collect(distinct aps), edges: collect(distinct edges)}")
    for idx, node in enumerate(graphJSON['nodes']):
        graphJSON['nodes'][idx] = {"data": node,
                                   "selected": 'false', "group": "nodes"}

        node['type'] = node['type'][0]
        if node['type'] == "Client":
            graphJSON['nodes'][idx]['style'] = {'background-color': "#00e600"}
        elif node['type'] == "Open":
            graphJSON['nodes'][idx]['style'] = {'background-color': "#fefefe"}
        elif node['type'] == "WEP":
            graphJSON['nodes'][idx]['style'] = {
                'background-color': "#fefefe", 'border-color': '00e600'}
        elif node['type'] == "WPA":
            graphJSON['nodes'][idx]['style'] = {'background-color': "#1b4ae4"}
        elif node['type'] == "WPA2":
            graphJSON['nodes'][idx]['style'] = {'background-color': "#e7890f"}
        else:
            graphJSON['nodes'][idx]['style'] = {
                'background-color': "#8000ff", 'border-style': 'dashed'}

    for idx, edge in enumerate(graphJSON['edges']):
        graphJSON['edges'][idx] = {"data": edge,
                                   "selected": 'false', "group": "edges"}
        if edge['name'] == "Probes":
            graphJSON['edges'][idx]['style'] = {
                'line-color': "yellow", 'line-style': 'dashed'}
        if edge['name'] == "AssociatedTo":
            graphJSON['edges'][idx]['style'] = {
                'line-color': "red", 'width': 6}

    data = json.dumps(graphJSON, indent=4)
    dbfile.write(data)


def url_ok(url):
    try:
        r = requests.get(url)
        if r.status_code == 200:
            return True
    except:
        return False

###FLASK SETUP###
@log_manager.user_loader
def load_user(userId):
    return User(userId)


@app.after_request
def add_header(r):
    '''Ensure browser does not cache files'''
    r.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    r.headers["Pragma"] = "no-cache"
    r.headers["Expires"] = "0"
    r.headers['Cache-Control'] = 'public, max-age=0'
    return r


@app.route('/')
def index():
    if current_user.is_authenticated:
        return render_template('index.html')
    else:
        return redirect(url_for('login'))


@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == "GET":
        return render_template('login.html')

    user = request.form.get("uname")
    pwd = request.form.get("psw")
    try:
        graph = Graph(user=user, password=pwd)
    except:
        return render_template('login.html')

    neo = User(1)
    login_user(neo)
    file = True
    if file:
        tables = open(CSV_FILE, "r").read().split("\n\n")
        
        # Clean up AP table
        bssidData = cleanup(tables[0])
        bssidDF = pd.read_csv(io.StringIO(bssidData), header=0)

        # Clean up client tables
        stationData = cleanup(tables[1], station=True)
        stationDF = pd.read_csv(io.StringIO(
            stationData), quotechar="|", header=0)

        # Change N/A to empty strings. Create dictionaries.
        bssidDF.fillna("", inplace=True)
        stationDF.fillna("", inplace=True)
        bssidDict = bssidDF.to_dict(orient='records')
        stationDict = stationDF.to_dict(orient='records')

        ##########GRAPH SETUP###############
        if FLUSH_DB:
            graph.delete_all()

        cpg(graph, stationDict, bssidDict)
        writeJson(graph)

        return redirect(url_for('index'))


@app.route("/export", methods=["POST"])
def export():
    name = request.json['name']
    img = request.json['data']
    if GUI:
        save = webview.create_file_dialog(dialog_type=webview.SAVE_DIALOG, save_filename=name, file_types=('PNG File (*.png)',))
        path = save[0]
    else:
        root = tk.Tk()
        root.withdraw()
        path = filedialog.asksaveasfilename(title="Export",filetypes = (("PNG files","*.png"),))
    if path:
        with open(path, "wb") as imgFile:
            imgFile.write(base64.b64decode(img))
            imgFile.close()
            return jsonify({'result': 'ok'})
    else:
        return jsonify({'result': 'canceled'})


@app.route("/fullscreen")
def toggleFull():
    if GUI:
        webview.toggle_fullscreen()
    return jsonify({'result': 'ok'})

#MAIN THREAD START#


def start_server():
    app.run(host='0.0.0.0', port=58008)


if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument("--no-flush", help="Do not flush the database before processing", action="store_true")
    parser.add_argument("--manuf", help="Update the Wireshark OUI lookup file", action="store_true")
    parser.add_argument("--gui", help="Attempt to launch app in a GUI instead of browser (may not work)", action="store_true")
    parser.add_argument("csvfile", help="Airodump-ng formatted CSV", type=argparse.FileType('r'))

    options = parser.parse_args()
    if options.no_flush:
        FLUSH_DB = False
    if options.manuf:
        MANUF_UPDATE = True
    if options.gui:
        GUI = True

    CSV_FILE = str(options.csvfile.name)

    t = threading.Thread(target=start_server)
    t.daemon = True
    t.start()

    url = "http://localhost:58008"
    while not url_ok(url):
        sleep(1)

    if GUI:
        webview.create_window("BEACONGRAPH", url, min_size=(1030, 740), confirm_quit=True, text_select=True)
        exit(0)
    else:
        webbrowser.open("http://localhost:58008", new=2)

    try:
        while True:
            sleep(1)

    except KeyboardInterrupt:
        print("exiting")
        exit(0)