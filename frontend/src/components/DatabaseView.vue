<template>
  <div class="database-view">
    <q-list class="database-sections">
      <q-expansion-item
        class="database-section"
        dense-toggle
        default-opened
        expand-separator
        label="Database Overview"
      >
        <div class="database-section-content">
          <q-table
            :columns="statsColumns"
            :data="statsSummary"
            bordered
            dark
            card-class="bg-grey-9 text-white"
            dense
            hide-header
            hide-bottom
            separator="cell"
            title="Database Stats"
          />
          <q-separator inset />
          <q-table
            :columns="nodeColumns"
            :data="currentNodeSummary"
            :pagination="pagination"
            :rows-per-page-options="[0]"
            bordered
            card-class="bg-black text-white"
            dense
            dark
            hide-pagination
            row-key="name"
            no-data-label="No Results"
            separator="cell"
            class="node-summary-table"
            table-class="text-white hide-scroll"
            table-header-class="text-white"
            title="Node Summary"
            virtual-scroll
          >
            <template v-slot:no-data>
              <div class="full-width row flex-center text-white q-gutter-sm">
                <span> No results </span>
                <q-btn
                  :ripple="{ center: true }"
                  color="indigo-10"
                  label="Refresh"
                  no-caps
                  @click="dbSummary"
                  :disabled="refreshing"
                />
              </div>
            </template>
          </q-table>
          <q-separator inset />

          <div class="q-pa-none q-ma-none uploader-wrap">
            <q-uploader
              @failed="handleUploadFailure"
              @uploaded="finishUpload"
              auto-upload
              bordered
              color="indigo-10"
              dark
              field-name="upload"
              :headers="getNeo4jCreds"
              hide-upload-btn
              label="Data Upload"
              no-thumbnails
              ref="uploader"
              style="width: 100%"
              :url="uploadUrl"
            >
            </q-uploader>

            <div class="row justify-end q-mt-sm">
              <q-btn
                color="negative"
                flat
                icon="delete_forever"
                label="Clear Ingested Data"
                no-caps
                :loading="clearing"
                @click="confirmClearData"
              />
            </div>
          </div>
        </div>
      </q-expansion-item>
    </q-list>
  </div>
</template>

<script>
import { mapState } from "vuex";

export default {
  name: "DatabaseView",
  computed: {
    ...mapState(["currentNodeSummary"]),
    uploadUrl() {
      if (typeof window !== "undefined") {
        return `${window.location.protocol}//${window.location.hostname}:9090/api/upload`;
      }

      if (process.env.UPLOAD_URL) {
        return process.env.UPLOAD_URL;
      }

      return "http://localhost:9090/api/upload";
    },
  },
  data() {
    return {
      clearing: false,
      refreshing: false,
      refreshTimers: [],
      pagination: {
        sortBy: "name",
        rowsPerPage: 0,
      },
      nodeColumns: [
        {
          name: "name",
          required: true,
          label: "Node Type",
          align: "left",
          field: "name",
        },
        { name: "count", required: true, label: "Count", field: "count" },
      ],
      statsColumns: [
        {
          name: "name",
          required: true,
          label: "Name",
          align: "left",
          field: "name",
        },
        { name: "value", required: true, label: "Value", field: "value" },
      ],
      statsSummary: [],
    };
  },

  created() {
    this.dbSummary();
    this.timer = setInterval(this.dbSummary, 5000);
  },

  beforeDestroy() {
    clearInterval(this.timer);
    this.refreshTimers.forEach((timer) => clearTimeout(timer));
  },

  methods: {
    dbSummary() {
      this.refreshing = true;
      this.$neo4j
        .run(
          "MATCH (n) RETURN count(labels(n)) AS count, labels(n) AS labels",
          {},
          {}
        )
        .then((res) => {
          let nodeSummary = [];
          res.records.forEach((record) => {
            let labels = record.get("labels");

            if (labels.length == 1) {
              nodeSummary.push({
                name: labels[0],
                count: record.get("count").toString(),
              });
            }

            if (labels.length > 1) {
              let primaryLabel = labels.filter(function (e) {
                return !(e == "Device");
              });
              nodeSummary.push({
                name: primaryLabel[0],
                count: record.get("count").toString(),
              });
            }
          });
          this.$store.dispatch("currentNodeSummary", nodeSummary);
        });

      this.statsSummary = [];
      let db = `${this.$store.getters.ssneo4j_scheme}://${this.$store.getters.ssneo4j_host}:${this.$store.getters.ssneo4j_port}`;
      this.statsSummary.push({ name: "Database", value: db });
      this.statsSummary.push({
        name: "User",
        value: this.$store.getters.ssneo4j_user,
      });
      this.refreshing = false;
    },
    getNeo4jCreds() {
      return [
        { name: "X-Neo4j-User", value: this.$store.getters.ssneo4j_user },
        { name: "X-Neo4j-Pass", value: this.$store.getters.ssneo4j_pass },
      ];
    },
    getNeo4jHeaderMap() {
      return {
        "X-Neo4j-User": this.$store.getters.ssneo4j_user,
        "X-Neo4j-Pass": this.$store.getters.ssneo4j_pass,
      };
    },
    clearGraphState() {
      this.$store.dispatch("clearGraphState");
    },
    clearData() {
      this.clearing = true;
      this.$axios
        .delete(this.uploadUrl.replace("/upload", "/data"), {
          headers: this.getNeo4jHeaderMap(),
        })
        .then(() => {
          this.clearGraphState();
          this.$q.notify({
            color: "positive",
            message: "Ingested data cleared.",
          });
          this.dbSummary();
        })
        .catch((err) => {
          this.$q.notify({
            color: "negative",
            message:
              (err.response && err.response.data && err.response.data.detail) ||
              err.message ||
              "Failed to clear ingested data.",
            timeout: 5000,
          });
        })
        .finally(() => {
          this.clearing = false;
        });
    },
    confirmClearData() {
      this.$q
        .dialog({
          dark: true,
          title: "Clear ingested data",
          message:
            "Delete all nodes and relationships currently stored in Neo4j? This cannot be undone.",
          cancel: true,
          persistent: true,
        })
        .onOk(() => {
          this.clearData();
        });
    },
    scheduleSummaryRefresh() {
      this.refreshTimers.forEach((timer) => clearTimeout(timer));
      this.refreshTimers = [0, 2000, 5000].map((delay) =>
        setTimeout(() => {
          this.dbSummary();
        }, delay)
      );
    },
    finishUpload() {
      this.$refs.uploader.reset();
      this.$q.notify({
        color: "positive",
        message: "Upload accepted. Ingestion may take a few seconds.",
      });
      this.scheduleSummaryRefresh();
    },
    handleUploadFailure(info) {
      this.$q.notify({
        color: "negative",
        message:
          (info && info.xhr && info.xhr.responseText) ||
          "Upload failed. Check the backend logs and file format.",
        timeout: 5000,
      });
    },
  },
};
</script>

<style lang="sass">
.database-view
  width: 100%

.database-sections
  background-color: transparent

.database-section
  background-color: $indigo-10
  color: white
  border-radius: 2px

.database-section-content
  display: flex
  flex-direction: column
  gap: 12px

.node-summary-table
  height: 36vh
  max-height: 320px

.uploader-wrap
  width: 100%
</style>
