<template>
  <div class="query-guide q-pa-xs">
    <q-list class="query-sections">
      <q-expansion-item
        class="query-section"
        dense-toggle
        default-opened
        expand-separator
        label="Query Help and Examples"
      >
        <q-card dark flat bordered class="guide-card bg-black text-white">
          <q-card-section>
            <div class="text-h6">Cypher Quick Start</div>
            <div class="text-body2 q-mt-sm">
              Cypher matches patterns in the graph. You usually start with
              <span class="query-token">MATCH</span>, optionally narrow results with
              <span class="query-token">WHERE</span>, and then choose what to show with
              <span class="query-token">RETURN</span>.
            </div>
          </q-card-section>

          <q-separator dark />

          <q-card-section>
            <div class="text-subtitle1">Pattern basics</div>
            <div class="q-mt-sm text-body2">
              <div><span class="query-token">(n)</span> any node</div>
              <div><span class="query-token">(n:Client)</span> a node with label Client</div>
              <div><span class="query-token">(a)-[r]-&gt;(b)</span> a directed relationship</div>
              <div><span class="query-token">n.Name</span> a property on a node</div>
            </div>
          </q-card-section>

          <q-separator dark />

          <q-card-section>
            <div class="text-subtitle1">A simple workflow</div>
            <div class="text-body2 q-mt-sm">
              1. Start broad: find nodes with <span class="query-token">MATCH (n) RETURN n LIMIT 25</span>.
            </div>
            <div class="text-body2">
              2. Filter by label: <span class="query-token">MATCH (n:Open) RETURN n</span>.
            </div>
            <div class="text-body2">
              3. Follow relationships: <span class="query-token">MATCH (c:Client)-[r]-&gt;(d:Device) RETURN c, r, d</span>.
            </div>
            <div class="text-body2">
              4. Narrow by property: <span class="query-token">MATCH (n) WHERE n.Name CONTAINS "wifi" RETURN n</span>.
            </div>
          </q-card-section>
        </q-card>

        <div class="query-examples-scroll q-mt-md">
          <q-list padding class="rounded-borders query-examples">
            <q-expansion-item
              v-for="query in queries"
              :key="`${query.title}`"
              class="query-example"
              dense-toggle
              expand-separator
              :label="query.title"
            >
              <q-card dark>
                <q-card-section>
                  <div class="text-caption text-grey-5 q-mb-sm">{{ query.explanation }}</div>
                  {{ query.cypher }}
                </q-card-section>
              </q-card>
            </q-expansion-item>
          </q-list>
        </div>
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
          title: "Start by showing a small sample of nodes",
          explanation: "Use this first to confirm the graph contains data and to inspect available properties.",
          cypher: "MATCH (n) RETURN n LIMIT 25",
        },
        {
          title: "Show all open access points",
          explanation: "Labels such as Open, WEP, WPA, and WPA2 describe access point security types.",
          cypher: "MATCH (a:Open) RETURN a",
        },
        {
          title: "Generate a client probe graph",
          explanation: "This recreates the classic probe-request view by showing each client and the networks it is probing for.",
          cypher: "MATCH (c:Client)-[r:Probes]->(d:Device) RETURN c, r, d",
        },
        {
          title: "Show all devices associated to an Open access point",
          explanation: "This finds open APs and any neighboring devices, regardless of relationship direction.",
          cypher: "MATCH (a:Open)-[b]-(c) RETURN *",
        },
        {
          title: "Show clients associated to another client (Mesh Network)",
          explanation: "This follows two hops to find client-to-client paths that may indicate mesh behavior.",
          cypher: "MATCH (a:Client)-[b]-(c:Client)-[d]-(e) RETURN *",
        },
        {
          title: "Show all Open and WEP access points",
          explanation: "Multiple MATCH clauses let you compare two groups in one result set.",
          cypher: "MATCH (a:Open) MATCH (b:WEP) RETURN *",
        },
        {
          title: "Show all Devices that have no associations",
          explanation: "WHERE NOT is useful for finding isolated nodes or missing links.",
          cypher: "MATCH (a) WHERE NOT (a)-[:Probes|Associated]->() RETURN *",
        },
        {
          title: "Find probes for a specific ESSID",
          explanation: "Use a relationship type and property filter together to narrow the graph to a topic.",
          cypher: 'MATCH (c:Client)-[:Probes]->(d:Device) WHERE d.Name = "xfinitywifi" RETURN c, d',
        },
        {
          title: "Search by partial device name",
          explanation: "CONTAINS is a simple way to explore uncertain property values.",
          cypher: 'MATCH (n) WHERE n.Name CONTAINS "wifi" RETURN n LIMIT 50',
        },
      ],
    };
  },
};
</script>

<style lang="sass">
.query-guide
  width: 100%

.query-sections
  background-color: transparent

.query-section
  background-color: $indigo-10
  color: white
  border-radius: 2px

.guide-card
  width: 100%

.query-examples-scroll
  max-height: 42vh
  overflow-y: auto

.query-examples
  width: 100%
  background-color: black

.query-example
  background-color: black

.query-token
  color: $indigo-4
</style>
