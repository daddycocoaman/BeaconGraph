# Changelog

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

