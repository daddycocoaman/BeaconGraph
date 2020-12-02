<template>
  <div id="cyto">
    <BeaconCytoscape />
    <DropdownQuery id="dropdown-query" />
    <InfoTabs id="info-tabs" />
    <MenuBar id="menu-bar" />
  </div>
</template>

<script>
import BeaconCytoscape from "components/BeaconCytoscape";
import InfoTabs from "components/InfoTabs";
import MenuBar from "components/MenuBar";
import DropdownQuery from "components/DropdownQuery";

export default {
  name: "MainLayout",
  components: { BeaconCytoscape, InfoTabs, MenuBar, DropdownQuery },
};
</script>
