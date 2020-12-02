<template>
  <div class="q-pa-xs row items-start q-gutter-none">
    <q-list padding class="rounded-borders" style="background-color: black">
      <q-expansion-item
        v-for="query in queries"
        :key="`${query.title}`"
        dense-toggle
        expand-separator
        :label="query.title"
        style="background-color: black"
      >
        <q-card dark>
          <q-card-section>
            {{ query.cypher }}
          </q-card-section>
        </q-card>
      </q-expansion-item>
    </q-list>
  </div>
</template>

<script>
export default {
  name: "QueryView",
  data() {
    return {
      queries: [
        {
          title: "Show all devices associated to an Open access point",
          cypher: "MATCH (a:Open)-[b]-(c) RETURN *",
        },
        {
          title: "Show clients associated to another client (Mesh Network)",
          cypher: "MATCH (a:Client)-[b]-(c:Client)-[d]-(e) RETURN *",
        },
        {
          title: "Show all Open and WEP access points",
          cypher: "MATCH (a:Open) MATCH (b:WEP) RETURN *",
        },
        {
          title: "Show all Devices that have no associations",
          cypher: "MATCH (a) WHERE NOT (a)-[:Probes|Associated]->() RETURN *",
        },
      ],
    };
  },
};
</script>
