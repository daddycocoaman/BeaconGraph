document.addEventListener('DOMContentLoaded', function(){
    $.getJSON("/static/db.json", function (data) {
          var cy = window.cy = cytoscape({
              container: document.getElementById('cy'),
              elements: data,
              style: [
                  {
                      selector: 'node',
                      style: {
                          'content': 'data(name)',
                          'color': 'white',
                          'font-size': 12,
                          'text-valign': 'bottom',
                          'text-halign': 'center',
                          'background-fit': 'contain',
                          'background-clip': 'none',
                          'padding': 10,
                          'text-background-color': '#00001a',
                          'text-background-opacity': 0.7,
                          'min-zoomed-font-size': 8 
                      }
                  }, 
                  {
                      selector: 'edge',
                      style: {
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
                      selector: 'core',
                      style: {
                          'active-bg-color': 'blue'          

                      }
                  }
              ],
              layout: {
                  name: 'cose-bilkent',
                  fit: 'true',
                  nodeDimensionsIncludeLabels: true,
                  nodeRepulsion: 8000
              },
              hideEdgesOnViewport: false,
              textureOnViewport: false,
              boxSelectionEnabled: false,
              componentSpacing: 100,
              nodeOverlap: 50,
              idealEdgeLength: 25,
              weaver: true
          });

          cy.on('cxttapstart', 'node', function (event){
              cy.$(event.target || event.cyTarget).select();
              displayInfo(event);
          });

          cy.on('click', 'node', function(event){
              displayInfo(event);
          });

          cy.ready(function(event){
              document.getElementById("loader").style.display = "none";
              cy.$(":selected").unselect();
          });

          function displayInfo(event){
                document.getElementById("name").innerHTML = cy.$(event.target || event.cyTarget).data('name') || "&nbsp;";
                document.getElementById("bssid").innerHTML =  cy.$(event.target || event.cyTarget).data('bssid') || "&nbsp;";                             
                document.getElementById("oui").innerHTML = cy.$(event.target || event.cyTarget).data('oui') || "&nbsp;";
                document.getElementById("type").innerHTML = cy.$(event.target || event.cyTarget).data('type') || "&nbsp;";
                document.getElementById("auth").innerHTML = cy.$(event.target || event.cyTarget).data('auth') || "&nbsp;";
                document.getElementById("cipher").innerHTML = cy.$(event.target || event.cyTarget).data('cipher') || "&nbsp;";
                document.getElementById("channel").innerHTML = cy.$(event.target || event.cyTarget).data('channel') || "&nbsp;";
                document.getElementById("speed").innerHTML = cy.$(event.target || event.cyTarget).data('speed') || "&nbsp;";
                document.getElementById("lan").innerHTML = cy.$(event.target || event.cyTarget).data('lan') || "&nbsp;";
          }

          var api = cy.viewUtilities({
            neighbor: function(node){
                return node.closedNeighborhood();
            },
            neighborSelectTime: 1000
        });

         function doFilter() {
            var value = document.getElementById("searchItem").value;
            if (value) { 
                var category = document.getElementById("category").value;
                filtered = cy.nodes().filter('node[' + category + ' @= \"' + value + '\"]');
                api.removeHighlights();
                if (filtered.length > 0) {
                    api.highlightNeighbors(filtered);
                    cy.fit(filtered);
                }
                else
                    alert("Nothing Found!");
         }}
        
         function exportPNG(data,name){
            
            img = data.replace(/^data:image\/(png);base64,/, "");
            var xhr = new XMLHttpRequest();
            var url = "http://localhost:58008/export";
            xhr.open("POST", url, true);
            xhr.setRequestHeader("Content-Type", "application/json");
            data = JSON.stringify({'name': name, 'data': img})
            xhr.send(data);
         }

          var cxtoptions = {
              // List of initial menu items
              menuItems: [
                {
                  id: 'highlight',
                  content: 'Highlight Neighbors',
                  selector: 'node',
                  onClickFunction: function () {
                      if(cy.$(":selected").length > 0)
                          api.highlightNeighbors(cy.$(":selected"));
                  }
                },
                {
                  id: 'removeHighlights',
                  content: 'Remove Highlights',
                  selector: 'node',
                  coreAsWell: true,
                  onClickFunction: function () {
                      cy.$(":selected").unselect();
                      api.removeHighlights();
                  }
                },
              ],
              // css classes that menu items will have
              menuItemClasses: [
                // add class names to this list
              ],
              // css classes that context menu will have
              contextMenuClasses: [
                // add class names to this list
              ]
          };
          cy.contextMenus( cxtoptions );

            document.getElementById("filter").addEventListener("click", function(){
                doFilter();
            });
        
            document.getElementById("searchItem").addEventListener("keypress", function (e){
                    var key = e.which || e.keyCode;
                    if (key === 13) {
                        doFilter();
                    }
            });

            document.getElementById("restore").addEventListener("click", function(){
                cy.$(":selected").unselect();
                api.removeHighlights();
                cy.fit();
            });

            document.getElementById("exportview").addEventListener("click", function(){
                var content = cy.png({bg: "black", scale: 4});
                exportPNG(content, 'exportView.png');
            });

            document.getElementById("exportfull").addEventListener("click", function(){
                var content = cy.png({bg: "black", full: true});
                exportPNG(content, 'exportFull.png');
            });

            document.addEventListener("keydown", function (e){
                var key = e.which || e.keyCode;
                if (key === 13 && e.altKey) {
                    var xhr = new XMLHttpRequest();
                    var url = "http://localhost:58008/fullscreen";
                    xhr.open("GET", url, true);
                    xhr.send();
                }
            });

      })});