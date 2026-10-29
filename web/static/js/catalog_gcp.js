// Copyright (c) 2026 K.N.Narin (github.com/narin-kura). All rights reserved.
// Non-commercial use only. Commercial use requires written permission: github.com/narin-kura
// See LICENSE for full terms.
//
// ArchLens — full Google Cloud product catalog for the interactive builder.
//
// Grouped by Google Cloud's own product categories (cloud.google.com/products).
// Shape matches web/static/js/catalog_aws.js — see that file's header comment
// for the field meanings. `service` is the real google_* Terraform resource
// type where one exists, so the parser and analyzers can key on it.
const GCP_PRODUCTS = [
  {g: 'Compute', items: [
    {id:'gcp_gce',           name:'Compute Engine',          type:'COMPUTE',    service:'google_compute_instance',              icon:'GCE'},
    {id:'gcp_instance_tmpl', name:'Instance Template',       type:'COMPUTE',    service:'google_compute_instance_template',     icon:'TMPL'},
    {id:'gcp_mig',           name:'Managed Instance Group',  type:'COMPUTE',    service:'google_compute_instance_group_manager',icon:'MIG'},
    {id:'gcp_ig',            name:'Instance Group',          type:'COMPUTE',    service:'google_compute_instance_group',        icon:'IG'},
    {id:'gcp_autoscaler',    name:'Autoscaler',               type:'OTHER',      service:'google_compute_autoscaler',            icon:'AS'},
    {id:'gcp_disk',          name:'Persistent Disk',         type:'STORAGE',    service:'google_compute_disk',                   icon:'PD'},
    {id:'gcp_region_disk',   name:'Regional Persistent Disk',type:'STORAGE',    service:'google_compute_region_disk',            icon:'RPD'},
    {id:'gcp_snapshot',      name:'Disk Snapshot',           type:'STORAGE',    service:'google_compute_snapshot',               icon:'SNP'},
    {id:'gcp_image',         name:'Custom Image',            type:'STORAGE',    service:'google_compute_image',                  icon:'IMG'},
    {id:'gcp_reservation',   name:'Compute Reservation',     type:'OTHER',      service:'google_compute_reservation',            icon:'RES'},
    {id:'gcp_sole_tenant',   name:'Sole-Tenant Node Group',  type:'COMPUTE',    service:'google_compute_node_group',             icon:'STN'},
    {id:'gcp_node_tmpl',     name:'Sole-Tenant Node Template',type:'OTHER',     service:'google_compute_node_template',          icon:'NT'},
    {id:'gcp_batch_job',     name:'Batch Job',                type:'COMPUTE',  service:'google_batch_job',                      icon:'BAT2'},
    {id:'gcp_spot_vm',       name:'Spot VM',                  type:'COMPUTE',   service:'spot_vm',                               icon:'SPOT', legacy:true},
    {id:'gcp_bare_metal',    name:'Bare Metal Solution',     type:'COMPUTE',    service:'bare_metal_solution',                   icon:'BMS', legacy:true},
    {id:'gcp_vmware_engine', name:'VMware Engine',            type:'COMPUTE',   service:'google_vmwareengine_private_cloud',     icon:'GVE'},
  ]},

  {g: 'Containers', items: [
    {id:'gcp_gke',           name:'GKE Cluster',              type:'CONTAINER', service:'google_container_cluster',              icon:'GKE'},
    {id:'gcp_gke_nodepool',  name:'GKE Node Pool',           type:'CONTAINER', service:'google_container_node_pool',            icon:'NP'},
    {id:'gcp_gke_autopilot', name:'GKE Autopilot',           type:'CONTAINER', service:'google_container_cluster',              icon:'AUTO', extraCats:['gcp']},
    {id:'gcp_cloudrun',      name:'Cloud Run',                type:'SERVERLESS',service:'google_cloud_run_v2_service',           icon:'CR'},
    {id:'gcp_cloudrun_job',  name:'Cloud Run Job',           type:'SERVERLESS', service:'google_cloud_run_v2_job',               icon:'CRJ'},
    {id:'gcp_artifactreg',   name:'Artifact Registry',       type:'CONTAINER',  service:'google_artifact_registry_repository',   icon:'GAR'},
    {id:'gcp_gke_hub',       name:'Anthos / Fleet',           type:'CONTAINER', service:'google_gke_hub_membership',             icon:'ANT'},
    {id:'gcp_binauthz',      name:'Binary Authorization',    type:'IAM',        service:'google_binary_authorization_policy',    icon:'BAZ'},
    {id:'gcp_container_reg', name:'Container Registry (legacy)',type:'CONTAINER',service:'container_registry_legacy',            icon:'GCR', legacy:true},
  ]},

  {g: 'Serverless', items: [
    {id:'gcp_cf1',           name:'Cloud Functions (1st gen)',type:'SERVERLESS',service:'google_cloudfunctions_function',        icon:'GCF1'},
    {id:'gcp_cf2',           name:'Cloud Functions (2nd gen)',type:'SERVERLESS',service:'google_cloudfunctions2_function',       icon:'GCF2'},
    {id:'gcp_appengine',     name:'App Engine',               type:'SERVERLESS',service:'google_app_engine_application',        icon:'GAE'},
    {id:'gcp_appengine_std', name:'App Engine Standard Version',type:'SERVERLESS',service:'google_app_engine_standard_app_version',icon:'GAES'},
    {id:'gcp_appengine_flex',name:'App Engine Flexible Version',type:'SERVERLESS',service:'google_app_engine_flexible_app_version',icon:'GAEF'},
    {id:'gcp_eventarc',      name:'Eventarc',                  type:'QUEUE',     service:'google_eventarc_trigger',               icon:'EVT'},
    {id:'gcp_workflows',     name:'Workflows',                 type:'OTHER',     service:'google_workflows_workflow',             icon:'WF'},
  ]},

  {g: 'Storage', items: [
    {id:'gcp_gcs',           name:'Cloud Storage',            type:'STORAGE',   service:'google_storage_bucket',                 icon:'GCS'},
    {id:'gcp_gcs_object',    name:'Storage Object',           type:'STORAGE',   service:'google_storage_bucket_object',          icon:'OBJ'},
    {id:'gcp_filestore',     name:'Filestore',                 type:'STORAGE',  service:'google_filestore_instance',             icon:'FS'},
    {id:'gcp_netapp_pool',   name:'NetApp Volumes — Storage Pool',type:'STORAGE',service:'google_netapp_storage_pool',           icon:'NAP'},
    {id:'gcp_netapp_volume', name:'NetApp Volumes — Volume',  type:'STORAGE',   service:'google_netapp_volume',                  icon:'NAV'},
    {id:'gcp_transfer',      name:'Storage Transfer Service', type:'OTHER',     service:'google_storage_transfer_job',           icon:'STS'},
    {id:'gcp_transfer_appl', name:'Transfer Appliance',       type:'OTHER',     service:'transfer_appliance',                    icon:'TAP', legacy:true},
  ]},

  {g: 'Databases', items: [
    {id:'gcp_cloudsql',      name:'Cloud SQL Instance',       type:'DATABASE',  service:'google_sql_database_instance',          icon:'SQL'},
    {id:'gcp_cloudsql_db',   name:'Cloud SQL Database',       type:'OTHER',     service:'google_sql_database',                   icon:'DB'},
    {id:'gcp_cloudsql_user', name:'Cloud SQL User',           type:'IAM',       service:'google_sql_user',                       icon:'USR'},
    {id:'gcp_spanner',       name:'Spanner Instance',         type:'DATABASE',  service:'google_spanner_instance',               icon:'SPN'},
    {id:'gcp_spanner_db',    name:'Spanner Database',         type:'OTHER',     service:'google_spanner_database',               icon:'SPNDB'},
    {id:'gcp_firestore',     name:'Firestore',                 type:'DATABASE', service:'google_firestore_database',             icon:'FST'},
    {id:'gcp_bigtable',      name:'Bigtable Instance',        type:'DATABASE',  service:'google_bigtable_instance',              icon:'BGT'},
    {id:'gcp_bigtable_table',name:'Bigtable Table',           type:'OTHER',     service:'google_bigtable_table',                 icon:'BGTT'},
    {id:'gcp_alloydb',       name:'AlloyDB Cluster',          type:'DATABASE',  service:'google_alloydb_cluster',                icon:'ADB'},
    {id:'gcp_alloydb_inst',  name:'AlloyDB Instance',         type:'OTHER',     service:'google_alloydb_instance',               icon:'ADBI'},
    {id:'gcp_bigquery',      name:'BigQuery Dataset',         type:'DATABASE',  service:'google_bigquery_dataset',               icon:'BQ'},
    {id:'gcp_bigquery_tbl',  name:'BigQuery Table',           type:'OTHER',     service:'google_bigquery_table',                 icon:'BQT'},
    {id:'gcp_bigquery_conn', name:'BigQuery Connection',      type:'OTHER',     service:'google_bigquery_connection',            icon:'BQC'},
  ]},

  {g: 'Caching', items: [
    {id:'gcp_memorystore_redis', name:'Memorystore for Redis',type:'CACHE',     service:'google_redis_instance',                  icon:'MSR'},
    {id:'gcp_redis_cluster', name:'Memorystore for Redis Cluster',type:'CACHE', service:'google_redis_cluster',                  icon:'MSRC'},
    {id:'gcp_memcache',      name:'Memorystore for Memcached',type:'CACHE',     service:'google_memcache_instance',              icon:'MSM'},
  ]},

  {g: 'Networking', items: [
    {id:'gcp_vpc',           name:'VPC Network',              type:'NETWORK',   service:'google_compute_network',                icon:'VPC'},
    {id:'gcp_subnet',        name:'Subnetwork',                type:'NETWORK',  service:'google_compute_subnetwork',             icon:'SUB'},
    {id:'gcp_firewall',      name:'Firewall Rule',            type:'NETWORK',   service:'google_compute_firewall',               icon:'FW'},
    {id:'gcp_firewall_pol',  name:'Firewall Policy',          type:'NETWORK',   service:'google_compute_firewall_policy',        icon:'FWP'},
    {id:'gcp_route',         name:'Route',                     type:'NETWORK',  service:'google_compute_route',                  icon:'RT'},
    {id:'gcp_router',        name:'Cloud Router',             type:'NETWORK',   service:'google_compute_router',                 icon:'RTR'},
    {id:'gcp_nat',           name:'Cloud NAT',                 type:'NETWORK',  service:'google_compute_router_nat',             icon:'NAT'},
    {id:'gcp_router_peer',   name:'BGP Peer',                  type:'NETWORK',  service:'google_compute_router_peer',            icon:'BGP'},
    {id:'gcp_vpn_gw',        name:'Classic VPN Gateway',      type:'NETWORK',   service:'google_compute_vpn_gateway',            icon:'VPN'},
    {id:'gcp_ha_vpn_gw',     name:'HA VPN Gateway',           type:'NETWORK',   service:'google_compute_ha_vpn_gateway',         icon:'HVPN'},
    {id:'gcp_vpn_tunnel',    name:'VPN Tunnel',                type:'NETWORK',  service:'google_compute_vpn_tunnel',             icon:'TUN'},
    {id:'gcp_interconnect',  name:'Cloud Interconnect',       type:'NETWORK',   service:'google_compute_interconnect_attachment',icon:'ICA'},
    {id:'gcp_address',       name:'Static IP Address',        type:'NETWORK',   service:'google_compute_address',                icon:'IP'},
    {id:'gcp_global_address',name:'Global Static IP',         type:'NETWORK',   service:'google_compute_global_address',         icon:'GIP'},
    {id:'gcp_fwd_rule',      name:'Forwarding Rule',          type:'GATEWAY',   service:'google_compute_forwarding_rule',        icon:'FWR'},
    {id:'gcp_global_fwd_rule',name:'Global Forwarding Rule',  type:'GATEWAY',   service:'google_compute_global_forwarding_rule', icon:'GFWR'},
    {id:'gcp_backend_svc',   name:'Backend Service',          type:'GATEWAY',   service:'google_compute_backend_service',        icon:'BES'},
    {id:'gcp_backend_bucket',name:'Backend Bucket',           type:'GATEWAY',   service:'google_compute_backend_bucket',         icon:'BEB'},
    {id:'gcp_region_backend',name:'Regional Backend Service', type:'GATEWAY',   service:'google_compute_region_backend_service', icon:'RBES'},
    {id:'gcp_health_check',  name:'Health Check',             type:'MONITORING',service:'google_compute_health_check',           icon:'HC'},
    {id:'gcp_url_map',       name:'URL Map',                   type:'GATEWAY',  service:'google_compute_url_map',                icon:'UM'},
    {id:'gcp_https_proxy',   name:'HTTPS Proxy',              type:'GATEWAY',   service:'google_compute_target_https_proxy',     icon:'HTTPS'},
    {id:'gcp_http_proxy',    name:'HTTP Proxy',               type:'GATEWAY',   service:'google_compute_target_http_proxy',      icon:'HTTP'},
    {id:'gcp_tcp_proxy',     name:'TCP Proxy',                 type:'GATEWAY',  service:'google_compute_target_tcp_proxy',       icon:'TCP'},
    {id:'gcp_ssl_cert',      name:'SSL Certificate',          type:'IAM',       service:'google_compute_ssl_certificate',        icon:'CERT'},
    {id:'gcp_ssl_policy',    name:'SSL Policy',                type:'IAM',      service:'google_compute_ssl_policy',             icon:'SSLP'},
    {id:'gcp_armor',         name:'Cloud Armor',               type:'NETWORK',  service:'google_compute_security_policy',        icon:'ARM'},
    {id:'gcp_dns',           name:'Cloud DNS Zone',           type:'NETWORK',   service:'google_dns_managed_zone',               icon:'DNS'},
    {id:'gcp_dns_record',    name:'Cloud DNS Record',         type:'OTHER',     service:'google_dns_record_set',                 icon:'DNSR'},
    {id:'gcp_ncc_hub',       name:'Network Connectivity Hub', type:'NETWORK',   service:'google_network_connectivity_hub',       icon:'NCH'},
    {id:'gcp_ncc_spoke',     name:'Network Connectivity Spoke',type:'NETWORK',  service:'google_network_connectivity_spoke',     icon:'NCS'},
    {id:'gcp_psa',           name:'Private Service Access',   type:'NETWORK',   service:'google_service_networking_connection',  icon:'PSA'},
    {id:'gcp_peering',       name:'VPC Network Peering',      type:'NETWORK',   service:'google_compute_network_peering',        icon:'PEER'},
    {id:'gcp_pkt_mirror',    name:'Packet Mirroring',         type:'NETWORK',   service:'google_compute_packet_mirroring',       icon:'MIRR'},
    {id:'gcp_cert_mgr',      name:'Certificate Manager',      type:'IAM',       service:'google_certificate_manager_certificate',icon:'CM'},
  ]},

  {g: 'Security & Identity', items: [
    {id:'gcp_iam_binding',   name:'IAM Binding',               type:'IAM',       service:'google_project_iam_binding',            icon:'IAMB'},
    {id:'gcp_iam_member',    name:'IAM Member',                type:'IAM',       service:'google_project_iam_member',             icon:'IAMM'},
    {id:'gcp_svc_account',   name:'Service Account',          type:'IAM',       service:'google_service_account',                icon:'SVC'},
    {id:'gcp_svc_account_key',name:'Service Account Key',     type:'IAM',       service:'google_service_account_key',            icon:'KEY'},
    {id:'gcp_kms_ring',      name:'Cloud KMS Key Ring',       type:'IAM',       service:'google_kms_key_ring',                   icon:'KMSR'},
    {id:'gcp_kms_key',       name:'Cloud KMS Crypto Key',     type:'IAM',       service:'google_kms_crypto_key',                 icon:'KMS'},
    {id:'gcp_secret',        name:'Secret Manager Secret',    type:'IAM',       service:'google_secret_manager_secret',          icon:'SEC'},
    {id:'gcp_secret_ver',    name:'Secret Version',           type:'OTHER',     service:'google_secret_manager_secret_version',  icon:'SECV'},
    {id:'gcp_org_policy',    name:'Organization Policy',      type:'IAM',       service:'google_org_policy_policy',              icon:'ORGP'},
    {id:'gcp_acm_policy',    name:'Access Context Manager Policy',type:'IAM',   service:'google_access_context_manager_access_policy',icon:'ACMP'},
    {id:'gcp_vpc_sc',        name:'VPC Service Controls Perimeter',type:'IAM',  service:'google_access_context_manager_service_perimeter',icon:'VPCSC'},
    {id:'gcp_identity_platform',name:'Identity Platform',     type:'IAM',       service:'google_identity_platform_config',       icon:'IDP'},
    {id:'gcp_workload_identity',name:'Workload Identity Pool',type:'IAM',       service:'google_iam_workload_identity_pool',     icon:'WIP'},
    {id:'gcp_privateca',     name:'Certificate Authority Pool',type:'IAM',      service:'google_privateca_ca_pool',              icon:'CAP'},
    {id:'gcp_essential_contacts',name:'Essential Contacts',   type:'OTHER',     service:'google_essential_contacts_contact',     icon:'ESC'},
    {id:'gcp_asset_feed',    name:'Cloud Asset Inventory Feed',type:'MONITORING',service:'google_cloud_asset_project_feed',       icon:'CAI'},
    {id:'gcp_scc_source',    name:'Security Command Center Source',type:'MONITORING',service:'google_scc_source',               icon:'SCC'},
    {id:'gcp_scc_notify',    name:'SCC Notification Config',  type:'MONITORING',service:'google_scc_notification_config',        icon:'SCCN'},
  ]},

  {g: 'Data Analytics', items: [
    {id:'gcp_dataflow',      name:'Dataflow Job',             type:'COMPUTE',   service:'google_dataflow_job',                   icon:'DF'},
    {id:'gcp_dataproc',      name:'Dataproc Cluster',         type:'COMPUTE',   service:'google_dataproc_cluster',               icon:'DPR'},
    {id:'gcp_dataproc_wf',   name:'Dataproc Workflow Template',type:'OTHER',    service:'google_dataproc_workflow_template',     icon:'DPRW'},
    {id:'gcp_composer',      name:'Cloud Composer',           type:'OTHER',     service:'google_composer_environment',           icon:'CMP'},
    {id:'gcp_datafusion',    name:'Data Fusion',               type:'OTHER',    service:'google_data_fusion_instance',           icon:'DFU'},
    {id:'gcp_dataplex_lake', name:'Dataplex Lake',            type:'OTHER',     service:'google_dataplex_lake',                  icon:'DPL'},
    {id:'gcp_dataplex_zone', name:'Dataplex Zone',            type:'OTHER',     service:'google_dataplex_zone',                  icon:'DPLZ'},
    {id:'gcp_datastream',    name:'Datastream Stream',        type:'OTHER',     service:'google_datastream_stream',              icon:'DST'},
    {id:'gcp_datastream_conn',name:'Datastream Connection Profile',type:'OTHER',service:'google_datastream_connection_profile',  icon:'DSTC'},
    {id:'gcp_dataform',      name:'Dataform Repository',      type:'OTHER',     service:'google_dataform_repository',            icon:'DFM'},
    {id:'gcp_pubsub',        name:'Pub/Sub Topic',            type:'QUEUE',     service:'google_pubsub_topic',                   icon:'PS'},
    {id:'gcp_pubsub_sub',    name:'Pub/Sub Subscription',     type:'QUEUE',     service:'google_pubsub_subscription',            icon:'PSS'},
    {id:'gcp_pubsub_lite',   name:'Pub/Sub Lite Topic',       type:'QUEUE',     service:'google_pubsub_lite_topic',              icon:'PSL'},
  ]},

  {g: 'AI & Machine Learning', items: [
    {id:'gcp_vertex_endpoint', name:'Vertex AI Endpoint',     type:'SERVERLESS',service:'google_vertex_ai_endpoint',             icon:'VAIE'},
    {id:'gcp_vertex_dataset', name:'Vertex AI Dataset',       type:'DATABASE',  service:'google_vertex_ai_dataset',              icon:'VAID'},
    {id:'gcp_vertex_feature', name:'Vertex AI Feature Store',type:'DATABASE',  service:'google_vertex_ai_featurestore',         icon:'VAIF'},
    {id:'gcp_vertex_index',   name:'Vertex AI Vector Index', type:'DATABASE',  service:'google_vertex_ai_index',                icon:'VAII'},
    {id:'gcp_vertex_index_ep',name:'Vertex AI Index Endpoint',type:'SERVERLESS',service:'google_vertex_ai_index_endpoint',       icon:'VAIX'},
    {id:'gcp_vertex_metadata',name:'Vertex AI Metadata Store',type:'DATABASE', service:'google_vertex_ai_metadata_store',       icon:'VAIM'},
    {id:'gcp_vertex_tb',      name:'Vertex AI Tensorboard',  type:'MONITORING',service:'google_vertex_ai_tensorboard',          icon:'VAIT'},
    {id:'gcp_notebooks',      name:'Vertex AI Workbench Notebook',type:'COMPUTE',service:'google_notebooks_instance',           icon:'NB'},
    {id:'gcp_docai',          name:'Document AI Processor',  type:'SERVERLESS',service:'google_document_ai_processor',          icon:'DAI'},
  ]},

  {g: 'Developer Tools & CI/CD', items: [
    {id:'gcp_cloudbuild',    name:'Cloud Build Trigger',      type:'OTHER',     service:'google_cloudbuild_trigger',             icon:'GCB'},
    {id:'gcp_cloudbuild_conn',name:'Cloud Build Connection',  type:'OTHER',     service:'google_cloudbuildv2_connection',        icon:'GCBC'},
    {id:'gcp_sourcerepo',    name:'Cloud Source Repository',  type:'OTHER',     service:'google_sourcerepo_repository',          icon:'CSR'},
    {id:'gcp_clouddeploy',   name:'Cloud Deploy Pipeline',    type:'OTHER',     service:'google_clouddeploy_delivery_pipeline',  icon:'CD'},
    {id:'gcp_clouddeploy_tgt',name:'Cloud Deploy Target',     type:'OTHER',     service:'google_clouddeploy_target',             icon:'CDT'},
    {id:'gcp_apigee_org',    name:'Apigee Organization',      type:'GATEWAY',   service:'google_apigee_organization',            icon:'APO'},
    {id:'gcp_apigee_env',    name:'Apigee Environment',       type:'GATEWAY',   service:'google_apigee_environment',             icon:'APE'},
  ]},

  {g: 'Integration', items: [
    {id:'gcp_tasks',         name:'Cloud Tasks Queue',        type:'QUEUE',     service:'google_cloud_tasks_queue',              icon:'CTQ'},
    {id:'gcp_scheduler',     name:'Cloud Scheduler Job',      type:'OTHER',     service:'google_cloud_scheduler_job',            icon:'SCH'},
  ]},

  {g: 'Management & Governance', items: [
    {id:'gcp_monitor_alert', name:'Monitoring Alert Policy',  type:'MONITORING',service:'google_monitoring_alert_policy',        icon:'MAL'},
    {id:'gcp_monitor_chan',  name:'Monitoring Notification Channel',type:'MONITORING',service:'google_monitoring_notification_channel',icon:'MNC'},
    {id:'gcp_monitor_uptime',name:'Uptime Check',             type:'MONITORING',service:'google_monitoring_uptime_check_config', icon:'UPT'},
    {id:'gcp_logging_sink',  name:'Logging Sink',             type:'MONITORING',service:'google_logging_project_sink',           icon:'LOGS'},
    {id:'gcp_logging_metric',name:'Logging Metric',           type:'MONITORING',service:'google_logging_metric',                 icon:'LGM'},
    {id:'gcp_billing_budget',name:'Billing Budget',           type:'OTHER',     service:'google_billing_budget',                 icon:'BUD'},
    {id:'gcp_folder',        name:'Resource Manager Folder',  type:'OTHER',     service:'google_folder',                         icon:'FLD'},
    {id:'gcp_tag_key',       name:'Resource Tag Key',         type:'OTHER',     service:'google_tags_tag_key',                   icon:'TAGK'},
    {id:'gcp_tag_value',     name:'Resource Tag Value',       type:'OTHER',     service:'google_tags_tag_value',                 icon:'TAGV'},
  ]},

  {g: 'Healthcare & Media', items: [
    {id:'gcp_healthcare_ds', name:'Healthcare Dataset',       type:'DATABASE',  service:'google_healthcare_dataset',             icon:'HDS'},
    {id:'gcp_healthcare_fhir',name:'Healthcare FHIR Store',   type:'DATABASE',  service:'google_healthcare_fhir_store',          icon:'FHIR'},
    {id:'gcp_healthcare_dicom',name:'Healthcare DICOM Store', type:'DATABASE', service:'google_healthcare_dicom_store',         icon:'DICOM'},
    {id:'gcp_transcoder',    name:'Transcoder Job Template',  type:'OTHER',     service:'google_transcoder_job_template',        icon:'TRC'},
  ]},

  {g: 'Business Applications', items: [
    {id:'gcp_looker',        name:'Looker (Google Cloud core)',type:'COMPUTE',  service:'google_looker_instance',                icon:'LKR'},
    {id:'gcp_firebase_proj', name:'Firebase Project',         type:'OTHER',     service:'google_firebase_project',               icon:'FB'},
    {id:'gcp_firebase_web',  name:'Firebase Web App',         type:'OTHER',     service:'google_firebase_web_app',               icon:'FBW'},
    {id:'gcp_firebase_hosting',name:'Firebase Hosting Site',  type:'CDN',       service:'google_firebase_hosting_site',          icon:'FBH'},
    {id:'gcp_firebase_rtdb', name:'Firebase Realtime Database',type:'DATABASE', service:'google_firebase_database_instance',     icon:'FBRT'},
  ]},

  {g: 'CDN', items: [
    {id:'gcp_cdn',           name:'Cloud CDN',                 type:'CDN',      service:'cloud_cdn',                            icon:'CDN', legacy:true},
    {id:'gcp_media_cdn',     name:'Media CDN',                 type:'CDN',      service:'media_cdn',                            icon:'MCDN', legacy:true},
  ]},

  {g: 'Legacy / Classic', items: [
    {id:'gcp_iot_core',      name:'Cloud IoT Core (retired)', type:'QUEUE',     service:'cloud_iot_core',                        icon:'IOT', legacy:true},
    {id:'gcp_ml_engine',     name:'AI Platform (legacy ML Engine)',type:'COMPUTE',service:'ai_platform_legacy',                 icon:'MLE', legacy:true},
  ]},
];

window.GCP_CATALOG = GCP_PRODUCTS.flatMap(({g, items}) =>
  items.map(item => ({provider: 'gcp', cat: 'gcp', group: g, ...item}))
);
