(window["webpackJsonp"]=window["webpackJsonp"]||[]).push([[3],{"013f":function(e,t,s){"use strict";s.r(t);var o=function(){var e=this,t=e.$createElement,s=e._self._c||t;return s("q-layout",[s("q-page-container",[s("q-page",{staticClass:"window-height window-width row justify-center items-center",staticStyle:{background:"black",overflow:"hidden"}},[s("q-parallax",{attrs:{height:e.windowHeight},scopedSlots:e._u([{key:"media",fn:function(){return[s("video",{attrs:{width:"100%",height:"100%",autoplay:"",loop:"",muted:""},domProps:{muted:!0}},[s("source",{attrs:{type:"video/mp4",src:"goldenstars.mp4"}})])]},proxy:!0}])},[s("div",{staticClass:"column q-pa-lg"},[s("div",{staticClass:"row"},[s("img",{staticClass:"q-px-lg",staticStyle:{width:"auto",height:"auto","max-height":"500px"},attrs:{src:"logo.png"}}),s("q-card",{staticClass:"text-white",staticStyle:{"background-color":"transparent"}},[s("q-card-section",{staticStyle:{"background-color":"transparent"}},[s("q-form",{ref:"loginForm",staticClass:"q-px-sm q-pt-xl q-pb-lg q-mb-none q-mt-xl",on:{submit:function(t){return t.preventDefault(),t.stopPropagation(),e.onSubmit(t)}}},[s("q-input",{staticClass:"input-border-bluegrey q-pa-none q-mb-lg",staticStyle:{"background-color":"transparent"},attrs:{dense:"",type:"username",label:"Username","label-color":"grey",rules:[function(e){return!!e||"Field is required"}]},scopedSlots:e._u([{key:"prepend",fn:function(){return[s("q-icon",{attrs:{name:"person",color:"white"}})]},proxy:!0}]),model:{value:e.username,callback:function(t){e.username=t},expression:"username"}}),s("q-separator",{attrs:{vertical:"",inset:""}}),s("q-input",{staticClass:"input-border-bluegrey q-pa-none q-mb-lg",attrs:{type:"password",dense:"",label:"Password","label-color":"grey",rules:[function(e){return!!e||"Field is required"}]},scopedSlots:e._u([{key:"prepend",fn:function(){return[s("q-icon",{attrs:{name:"lock",color:"white"}})]},proxy:!0}]),model:{value:e.password,callback:function(t){e.password=t},expression:"password"}}),s("q-separator",{attrs:{vertical:"",inset:""}}),s("q-input",{staticClass:"input-border-bluegrey q-pa-none q-mb-lg",attrs:{type:"url",label:"Server","label-color":"grey",rules:[function(e){return!!e||"Field is required"}]},scopedSlots:e._u([{key:"prepend",fn:function(){return[s("q-icon",{attrs:{name:"mediation",color:"white"}})]},proxy:!0}]),model:{value:e.server,callback:function(t){e.server=t},expression:"server"}}),s("q-checkbox",{staticClass:"q-pb-none q-ma-xs",attrs:{"keep-color":"",label:"Remember Me",color:"indigo-10"},model:{value:e.remember,callback:function(t){e.remember=t},expression:"remember"}}),s("q-card-actions",{staticClass:"q-px-xs q-pb-none q-ma-xs"},[s("q-btn",{staticClass:"full-width text-white",attrs:{size:"lg",type:"submit",color:"indigo-10",label:"Login",disabled:e.submitted}})],1)],1)],1)],1)],1)])])],1)],1)],1)},r=[],n=s("2f62"),i={name:"Login",data(){return{windowHeight:1080,server:"bolt://localhost:7687",username:"neo4j",password:"",remember:!1,submitted:!1}},computed:Object(n["b"])(["ssneo4j_user","ssneo4j_pass","ssneo4j_host","ssneo4j_port","ssneo4j_scheme"]),created(){if(this.$nextTick(()=>{window.addEventListener("resize",this.onResize)}),this.ssneo4j_user&&this.ssneo4j_pass&&this.$store.getters.isLoggedIn){this.$neo4j.connect(this.ssneo4j_scheme,this.ssneo4j_host,this.ssneo4j_port,this.ssneo4j_user,this.ssneo4j_pass);const e=this.$neo4j.getSession();e.run("MATCH () RETURN 1 LIMIT 1").then(e=>{this.$store.dispatch("loggedIn"),this.$router.push("/dashboard")})}},beforeDestroy(){window.removeEventListener("resize",this.onResize)},methods:{onResize(){this.windowHeight=window.outerHeight},onSubmit(){this.submitted=!0,this.$refs.loginForm.validate().then(e=>{this.connect()}).catch(e=>{this.$q.notify({color:"red",message:e.message}),this.submitted=!1})},connect(){var e=this.server.split("://")[0],t=this.server.split("://")[1],s=t.split(":")[0],o=t.split(":")[1];this.$neo4j.connect("bolt",s,o,this.username,this.password);const r=this.$neo4j.getSession();r.run("MATCH () RETURN 1 LIMIT 1").then(t=>{this.$q.notify({color:"positive",message:"You have been successfully logged in."});var r={user:this.username,pass:this.password,host:s,port:o,scheme:e,remember:this.remember};this.$store.dispatch("setAuth",r),this.$router.push("/dashboard")}).catch(e=>{this.$q.notify({color:"red",message:"Login Failed"}),this.submitted=!1})},driver(){return this.$neo4j.getDriver()},testQuery(){const e=this.$neo4j.getSession();e.run("MATCH (n) RETURN count(n) AS count").then(e=>{}).then(()=>{e.close()})}}},a=i,l=(s("c3b4"),s("2877")),c=s("4d5a"),u=s("09e3"),d=s("9989"),p=s("639d"),h=s("f09f"),m=s("a370"),b=s("0378"),g=s("27f9"),q=s("0016"),w=s("eb85"),f=s("8f8e"),y=s("4b7e"),v=s("9c40"),x=s("eebe"),j=s.n(x),k=Object(l["a"])(a,o,r,!1,null,null,null);t["default"]=k.exports;j()(k,"components",{QLayout:c["a"],QPageContainer:u["a"],QPage:d["a"],QParallax:p["a"],QCard:h["a"],QCardSection:m["a"],QForm:b["a"],QInput:g["a"],QIcon:q["a"],QSeparator:w["a"],QCheckbox:f["a"],QCardActions:y["a"],QBtn:v["a"]})},"0434":function(e,t,s){},c3b4:function(e,t,s){"use strict";var o=s("0434"),r=s.n(o);r.a}}]);