# Changelog

## v1.0.0-beta - 2020-12-01

- Another complete overhaul of BeaconGraph. New frontend, backend, and deployed via Docker.

## v0.69 - 2019-05-15

- Complete overhaul of BeaconGraph. Now uses Dash Cytoscape as the graph renderer inside of PyQt5 widgets.
- Removed all command line options. Interaction is now done via GUI.
- OUI parsing is now done via https://macaddress.io provided database.

## v0.2 - 2018-10-20

### Added

- Added `--parse` option to parse CSV files into neo4j database without launching app.
- Added `-a` for airodump-ng formatted CSVs. This will help expand different formats to different switches.
- Added AP parsing for airodump-ng to include APs that were discovered but had no clients.

### Changed

- Fixed major parsing issue that removed Probed relatioships when adding AssociatedTo relationships.
- Fixed order of loading logo to main page. Logo now displays properly while Cytoscape renders.
- Minor CSS/Javascript changes.

## v0.1.1 - 2018-10-18

### Added

- Added `--gui` option to make GUI launch optional. BeaconGraph now launches browser by default.
- Added multiple requirement files based on need of user.

### Changed

- Minor CSS changes.
