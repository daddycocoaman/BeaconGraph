function importAll(r) {
  let images = {};
  r.keys().map((item, index) => {
    images[item.replace("./", "")] = r(item);
  });
  return images;
}

const images = importAll(
  require.context("./assets/nodes", false, /\.(png|jpe?g|svg)$/)
);

const config = {
  wheelSensitivity: 0.2,
  style: [
    {
      selector: "node",
      style: {
        label: "data(name)",
        color: "white",
        "font-size": 8,
        "text-valign": "bottom",
        "text-halign": "center",
        "background-fit": "contain",
        "background-clip": "none",
        "text-background-color": "#00001a",
        "text-background-opacity": 0.7,
        "text-background-padding": 1,
        "text-background-shape": "roundrectangle",
        "min-zoomed-font-size": 8,
        "background-opacity": 1,
        "overlay-color": "white",
        "font-family": "Cascadia Mono",
        "z-index": 10,
      },
    },
    {
      selector: "edge",
      style: {
        width: "2px",
        "target-arrow-shape": "triangle",
        "target-arrow-color": "white",
        "target-arrow-fill": "filled",
        "control-point-step-size": "100px",
        label: "data(type)",
        color: "white",
        "line-color": "#666362",
        "font-size": "8",
        "curve-style": "bezier",
        "text-rotation": "autorotate",
        "text-valign": "top",
        "text-margin-y": -10,
        "text-background-color": "#00001a",
        "min-zoomed-font-size": 8,
        "font-family": "Cascadia Mono",
      },
    },
    {
      selector: ":selected",
      style: {
        "border-opacity": 1,
        opacity: 1,
        color: "#ff7f00",
        "z-index": 9999,
      },
    },
    {
      selector: ".incomingEdge",
      style: {
        "line-color": "#FC6A03",
        "z-index": 9999,
        opacity: 1,
      },
    },
    {
      selector: ".outgoingEdge",
      style: {
        "line-color": "#A0FA82",
        "z-index": 9999,
        opacity: 1,
      },
    },
    {
      selector: ".opacityDim",
      style: {
        "z-index": 9999,
        opacity: 0.3,
      },
    },
  ],
};

const NODE_LABELS = {
  Client: ["green", images["client.png"]],
  AP: ["#00ffd9", images["ap.png"]],
  Open: ["white", images["open.png"]],
  WEP: ["red", images["wep.png"]],
  WPA: ["yellow", images["wpa.png"]],
  WPA2: ["orange", images["wpa2.png"]],
  WPA3: ["pink", images["wpa3.png"]],
};

for (var [key, value] of Object.entries(NODE_LABELS)) {
  let nodeStyle = {
    selector: `node[type = "${key}"]`,
    style: {
      "background-image": value[1],
      "background-color": value[0],
    },
  };
  config.style.push(nodeStyle);
}
export default config;
