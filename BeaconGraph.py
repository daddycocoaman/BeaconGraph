#!/usr/bin/env python
import dash
import json
import asyncio
import sys
import threading
import dash_daq as daq
import dash_html_components as html
import dash_cytoscape as cyto
import dash_core_components as dcc
import bg_parsers
from collections import Counter
from time import sleep
from dash.dependencies import Output, Input, State
from PyQt5.QtWidgets import QApplication
from PyQt5.QtWebEngineWidgets import QWebEngineView
from bg_gui import Form, BeaconView

class Beacongraph():
    def __init__(self, neo, parent=None):
        self.app = dash.Dash("BeaconGraph")
        self.app.title = "BeaconGraph"
        elements = neo.initialQuery()

        self.app.layout = html.Div(className="container", children=[
            html.Div(className="pageDiv", children=[
            cyto.Cytoscape(
                id='cytoscape',
                layout={'name': 'cose',
                        'weaver': True,
                        'componentSpacing': 130,
                        'nodeRepulsion' : 150000,
                        'nodeOverlap' : 200,
                        'idealEdgeLength': 100,
                        'nodeDimensionsIncludeLabels': True,
                        'padding': 200,
                        'fit': True},
                style={'width': '100%', 'height': "100%"},
                elements={},
                stylesheet=[
                    {
                        'selector': 'node',
                        'style': {
                            'content': 'data(name)',
                            'color': 'white',
                            'font-family': 'Fira Mono',
                            'font-size': 12,
                            'text-valign': 'bottom',
                            'text-halign': 'center',
                            'background-fit': 'contain',
                            'background-clip': 'none',
                            'text-background-color': '#00001a',
                            'text-background-opacity': 0.7,
                            'text-background-padding': 2,
                            'text-background-shape': 'roundrectangle',
                            'min-zoomed-font-size': 8 
                        }
                    }, 
                    {
                        'selector': 'edge',
                        'style': {
                            'width': '2px',
                            'target-arrow-shape': 'triangle-backcurve',
                            'target-arrow-color': 'white',
                            'target-arrow-fill': 'hollow',
                            'control-point-step-size': '140px',
                            'label': 'data(name)',
                            'color': 'white',
                            'font-size': '10',
                            'curve-style': 'bezier',
                            'text-rotation': 'autorotate',
                            'text-valign': 'top',
                            'text-margin-y': -10,
                            'text-background-color': '#00001a',
                            'min-zoomed-font-size': 8  
                        }
                    },
                    {
                        'selector': 'core',
                        'style': {
                            'active-bg-color': 'blue'          
                        }
                    },
                    {
                        'selector': 'node[type = "Client"]',
                        'style': {
                            'background-color': neo.CLIENT_COLOR          
                        }
                    },
                    {
                        'selector': 'node[type = "Open"]',
                        'style': {
                            'background-color': neo.OPEN_COLOR          
                        }
                    },
                    {
                        'selector': 'node[type = "WEP"]',
                        'style': {
                            'background-color': neo.WEP_COLOR,           
                        }
                    },
                    {
                        'selector': 'node[type = "WPA"]',
                        'style': {
                            'background-color': neo.WPA_COLOR          
                        }
                    },
                    {
                        'selector': 'node[type = "WPA2"]',
                        'style': {
                            'background-color': neo.WPA2_COLOR          
                        }
                    },
                    {
                        'selector': 'node[type = "AP"]',
                        'style': {
                            'background-color': neo.AP_COLOR          
                        }
                    },
                    {
                        'selector': 'edge[name = "Probes"]',
                        'style': {
                            'line-color': neo.PROBE_COLOR, 
                            'line-style': 'dashed'         
                        }
                    },
                    {
                        'selector': 'edge[name = "AssociatedTo"]',
                        'style': {
                            'line-color': neo.ASSOC_COLOR, 
                            'width': 6         
                        }
                    }
                ]
            )]),

            #Legend - bottom left
            html.Div(id='legend-div', className='legend', children=[
            ]),

            #Tabs - upper right
            html.Div([
                dcc.Tabs(id="data-tabs", 
                value='db-info',
                parent_className='custom-tabs', 
                className='custom-tabs-container', children=[
                    dcc.Tab(label="Database", value='db-info', className='custom-tab', children=[
                        html.Div(id='db-content-div', children=[
                            html.Pre(id='db-content', className="dbinfocontent"),
                            dcc.ConfirmDialogProvider(id='deletedb-provider', message='Are you sure you want to delete the DB?', children=[
                                html.Button('Delete DB', className="bgbutton")   
                        ]),
                            html.Div(id="hiddendb-div")
                    ])]),
                    dcc.Tab(label="Node Info", value="node-data", className='custom-tab', children=[
                        html.Div(id='filter-search-div', className='filtersearch',children=[
                            html.Table(id='filter-table', className='filtertable', children=[
                                html.Tr(className="tablerows", children=[
                                    html.Td(className="filtername", children=[
                                        dcc.Dropdown(id='filtername-dropdown', searchable=False,clearable=False, options=[
                                        {'label': 'Name', 'value': 'name'},
                                        {'label': 'BSSID', 'value': 'bssid'},
                                        {'label': 'OUI', 'value': 'oui'},
                                        {'label': 'Type', 'value': 'type'},
                                        {'label': 'Auth', 'value': 'auth'},
                                        {'label': 'Cipher', 'value': 'cipher'},
                                        {'label': 'Channel', 'value': 'channel'},
                                        {'label': 'Speed', 'value': 'speed'},
                                        {'label': 'LAN IP', 'value': 'lan'}
                                        ], value='name')
                                    ]),
                                    html.Td(className='filtervalue', children=dcc.Dropdown(id='filtervalue-dropdown', placeholder="Search", multi=True, options=neo.names))
                                ]),
                            ]),
                        html.Div(id='node-content-div', children=[
                            html.Pre(id='node-content', className="nodeinfocontent")
                        ])
                    ])]),
                    dcc.Tab(label="Queries", value="presets", className='custom-tab', children=[
                        html.Div(id='queries-content-div', children=[
                            html.Pre(id='queries-content', className="dbinfocontent")
                    ])]),
                    dcc.Tab(label="Settings", value="settings", className='custom-tab', children=[
                        html.Div(id='settings-content-div', children=[
                            
                    ])])    
                ])
            ]),

            #Lower right
            html.Div(id='log-div', children=[
                html.Pre(id='log-content', className="logDiv")
            ]),

            #Icons - upper left
            html.Div(className="functionIcons", children=[
                dcc.Upload(id="upload-data", multiple=True, children=[
                    html.I(id="upload-button", className="material-icons md-24 md-light tooltip", children=["cloud_upload",
                        html.Span(className="tooltiptext", children="Upload Data")])])
                #html.I(id="export-button", className="material-icons md-24 md-light tooltip", children=["camera_enhance",
                    #html.Span(className="tooltiptext", children="Export Data")])
            ]),

            html.Div(id='hidden-upload-div')
        ])

        @self.app.callback(Output('cytoscape', 'elements'), [Input('filtervalue-dropdown', 'value')], [State("filtername-dropdown", "value")])
        def handleSearch(value, prop):
            if value and not neo.INITIAL:
                return neo.searchQuery(value, prop)
            else:
                return {}

        @self.app.callback(Output('node-content', 'children'), [Input('cytoscape', 'tapNodeData'), Input('data-tabs', 'value')])
        def displayTapNodeData(data, tab):
            if not data:
                data = {}

            content = html.Table(id='data-table', className='nodetable', children=[
                makeTableRow("NAME", data.get('name') or "-"),
                makeTableRow("BSSID", data.get('bssid') or "-"),
                makeTableRow("OUI", data.get('oui') or "-"),
                makeTableRow("TYPE", data.get('type') or "-"),
                makeTableRow("AUTH", data.get('auth') or "-"),
                makeTableRow("CIPHER", data.get('cipher') or "-"),
                makeTableRow("CHANNEL", data.get('channel') or "-"),
                makeTableRow("SPEED", data.get('speed') or "-"),
                makeTableRow("LAN IP", data.get('lan') or "-")
                ])
            return content

        @self.app.callback(Output('data-tabs', 'value'), [Input('cytoscape', 'tapNodeData')])
        def switchToNodeTab(data):
            return "node-data"

        def makeTableRow(name, value):
            return html.Tr(className="tablerows", children=[
                        html.Td(className="rowname", children=name),
                        html.Td(className="rowvalue", children=value)
                    ])

        @self.app.callback(Output('filtervalue-dropdown', 'options'), [Input('cytoscape', 'elements'), 
                    Input('filtername-dropdown', 'value'), Input('hidden-upload-div', 'children'), Input('hiddendb-div', 'children')])
        def updateSearchNames(eles, searchName, uploadEntry, hiddenDB):
            searchOpts = {'name': neo.getNames, 'bssid': neo.getBssids, 'oui': neo.getOUIs, 'type': neo.getTypes, 
                            'auth': neo.getAuths, 'cipher': neo.getCiphers, 'channel': neo.getChannels, 'speed': neo.getSpeeds, 'lan': neo.getLanIPs}
            
            return [{'label': opt, 'value': opt} for opt in searchOpts[searchName]()]

        @self.app.callback(Output('db-content', 'children'), [Input('cytoscape', 'elements'), 
                            Input('hidden-upload-div', 'children'), Input('hiddendb-div', 'children')])
        def displayDBData(eles, uploadEntry, hiddenDB):
            stats = neo.getDbStats()
            content = html.Table(id='data-table', className='nodetable', children=[
                makeTableRow("DB Address", neo.uri or "-"),
                makeTableRow("DB User", neo.user or "-"),
                makeTableRow("Clients", stats['Client'] or "0"),
                makeTableRow("Probed APs", stats['AP'] or "0"),
                makeTableRow("WPA2", stats['WPA2'] or "0"),
                makeTableRow("WPA", stats['WPA'] or "0"),
                makeTableRow("WEP", stats['WEP'] or "0"),
                makeTableRow("Open", stats['Open'] or "0"),
                makeTableRow("Probes", stats['Probes'] or "0"),
                makeTableRow("Associations", stats['Assoc'] or "0")        
                ])

            return content    

        @self.app.callback(Output('legend-div', 'children'), [Input('cytoscape', 'elements')])
        def updateLegend(eles):
            if eles.get('nodes'):
                eleCounter = Counter([ele['data']['type'] for ele in eles['nodes']])
            else:
                eleCounter = {}

            return html.Table(id='data-table', children=[
                    html.Tr(className="tablerows", children=[
                        html.Td(className="legendindicator", children=[daq.Indicator(id='WPA2-led', value="True", color=neo.WPA2_COLOR)]),
                        html.Td(className="legendvalue", children="WPA2"),
                        html.Td(className="legendvalue", children=eleCounter.get('WPA2') or "-")
                ]),
                    html.Tr(className="tablerows", children=[
                        html.Td(className="legendindicator", children=[daq.Indicator(id='WPA-led', value="True", color=neo.WPA_COLOR)]),
                        html.Td(className="legendvalue", children="WPA"),
                        html.Td(className="legendvalue", children=eleCounter.get('WPA') or "-")
                ]),
                    html.Tr(className="tablerows", children=[
                        html.Td(className="legendindicator", children=[daq.Indicator(id='WEP-led', value="True", color=neo.WEP_COLOR)]),
                        html.Td(className="legendvalue", children="WEP"),
                        html.Td(className="legendvalue", children=eleCounter.get('WEP') or "-")
                ]),
                    html.Tr(className="tablerows", children=[
                        html.Td(className="legendindicator", children=[daq.Indicator(id='Open-led', value="True", color=neo.OPEN_COLOR)]),
                        html.Td(className="legendvalue", children="Open"),
                        html.Td(className="legendvalue", children=eleCounter.get('Open') or "-")
                ]),
                    html.Tr(className="tablerows", children=[
                        html.Td(className="legendindicator", children=[daq.Indicator(id='Client-led', value="True", color=neo.CLIENT_COLOR)]),
                        html.Td(className="legendvalue", children="Client"),
                        html.Td(className="legendvalue", children=eleCounter.get('Client') or "-")
                ]),
                    html.Tr(className="tablerows", children=[
                        html.Td(className="legendindicator", children=[daq.Indicator(id='AP-led', value="True", color=neo.AP_COLOR)]),
                        html.Td(className="legendvalue", children="AP"),
                        html.Td(className="legendvalue", children=eleCounter.get('AP') or "-")
                ]),
            ])

        @self.app.callback(Output('hidden-upload-div', 'children'), [Input('upload-data', 'contents')])
        def handleUpload(contentList):
            if contentList is not None:
                for content in contentList:
                    dType, *data = bg_parsers.parseUpload(content)
                    neo.handleIncomingData(dType, data)
                    
            return ""

        @self.app.callback(Output('hiddendb-div', 'children'), [Input('deletedb-provider', 'submit_n_clicks')])
        def deleteDatabase(sub_clicks):
            if not sub_clicks:
                return ""
            neo.deleteDB()
            return ""

if __name__ == '__main__':
    qt_app  = QApplication(sys.argv)
    form = Form()
    form.show()
    qt_app.exec_()

    while form.isVisible():
        pass

    if form.LOGGEDIN:
        bg = Beacongraph(form.neo)
        thread = threading.Thread(target=bg.app.run_server, kwargs={'host':'0.0.0.0', 'port': 9001, 'debug': False, 'threaded': True})
        thread.daemon = True
        thread.start()

        sleep(1)
        view = BeaconView('http://localhost:9001')
        view.show()
        qt_app.exec_()
    #app.run_server(host='0.0.0.0', debug=True, threaded=True)