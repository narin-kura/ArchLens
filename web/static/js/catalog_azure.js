// Copyright (c) 2026 K.N.Narin (github.com/narin-kura). All rights reserved.
// Non-commercial use only. Commercial use requires written permission: github.com/narin-kura
// See LICENSE for full terms.
//
// ArchLens — full Azure product catalog for the interactive builder.
//
// Grouped by Azure's own product categories (azure.microsoft.com/products).
// Shape matches web/static/js/catalog_aws.js — see that file's header comment
// for the field meanings. `service` is the real azurerm/azuread Terraform
// resource type where one exists, so the parser and analyzers can key on it.
const AZURE_PRODUCTS = [
  {g: 'Compute', items: [
    {id:'az_vm',             name:'Virtual Machines',       type:'COMPUTE',    service:'azurerm_linux_virtual_machine',   icon:'VM'},
    {id:'az_vm_windows',     name:'Windows VM',             type:'COMPUTE',    service:'azurerm_windows_virtual_machine', icon:'WVM'},
    {id:'az_vmss',           name:'VM Scale Sets',          type:'COMPUTE',    service:'azurerm_linux_virtual_machine_scale_set', icon:'VMSS'},
    {id:'az_availset',       name:'Availability Sets',      type:'COMPUTE',    service:'azurerm_availability_set',        icon:'AVS'},
    {id:'az_dedicated_host', name:'Dedicated Host',         type:'COMPUTE',    service:'azurerm_dedicated_host',          icon:'DH'},
    {id:'az_spot_vm',        name:'Spot Virtual Machines',  type:'COMPUTE',    service:'azurerm_spot_virtual_machine',    icon:'SPOT'},
    {id:'az_gallery',        name:'Compute Gallery',        type:'STORAGE',    service:'azurerm_shared_image_gallery',    icon:'GAL'},
    {id:'az_batch',          name:'Batch',                  type:'COMPUTE',    service:'azurerm_batch_pool',              icon:'BAT'},
    {id:'az_cloudservices',  name:'Cloud Services (classic)',type:'COMPUTE',   service:'cloud_services_classic',          icon:'CSC', legacy:true},
    {id:'az_vmware',         name:'Azure VMware Solution',  type:'COMPUTE',    service:'azurerm_vmware_private_cloud',    icon:'AVS2'},
    {id:'az_sapHLI',         name:'SAP HANA Large Instances',type:'COMPUTE',   service:'sap_hana_large_instances',        icon:'SAP'},
    {id:'az_springapps',     name:'Azure Spring Apps',      type:'COMPUTE',    service:'azurerm_spring_cloud_service',    icon:'SPR'},
    {id:'az_automanage',     name:'Automanage',             type:'OTHER',      service:'azurerm_automanage_configuration',icon:'AMG'},
    {id:'az_pps',            name:'Proximity Placement Groups',type:'OTHER',   service:'azurerm_proximity_placement_group',icon:'PPG'},
  ]},

  {g: 'Containers', items: [
    {id:'az_aks',            name:'Azure Kubernetes Service',type:'CONTAINER', service:'azurerm_kubernetes_cluster',      icon:'AKS'},
    {id:'az_aci',            name:'Container Instances',    type:'CONTAINER',  service:'azurerm_container_group',         icon:'ACI'},
    {id:'az_containerapps',  name:'Container Apps',         type:'CONTAINER',  service:'azurerm_container_app',           icon:'ACA'},
    {id:'az_acr',            name:'Container Registry',     type:'CONTAINER',  service:'azurerm_container_registry',      icon:'ACR'},
    {id:'az_aro',            name:'Red Hat OpenShift (ARO)',type:'CONTAINER',  service:'azurerm_redhat_openshift_cluster',icon:'ARO'},
    {id:'az_servicefabric',  name:'Service Fabric',         type:'CONTAINER',  service:'azurerm_service_fabric_cluster',  icon:'SF'},
    {id:'az_sfmesh',         name:'Service Fabric Mesh',    type:'CONTAINER',  service:'service_fabric_mesh',             icon:'SFM', legacy:true},
    {id:'az_arc_k8s',        name:'Arc-enabled Kubernetes',  type:'CONTAINER', service:'azurerm_arc_kubernetes_cluster',  icon:'ARCK'},
    {id:'az_dapr',           name:'Dapr (Container Apps)',  type:'OTHER',      service:'azurerm_container_app_environment_dapr_component', icon:'DPR'},
  ]},

  {g: 'Storage', items: [
    {id:'az_blob',           name:'Blob Storage',           type:'STORAGE',    service:'azurerm_storage_account',         icon:'BLOB'},
    {id:'az_container',      name:'Storage Container',      type:'STORAGE',    service:'azurerm_storage_container',       icon:'CNT'},
    {id:'az_files',          name:'Azure Files',            type:'STORAGE',    service:'azurerm_storage_share',           icon:'FIL'},
    {id:'az_disk',           name:'Managed Disks',          type:'STORAGE',    service:'azurerm_managed_disk',            icon:'DSK'},
    {id:'az_disk_encset',    name:'Disk Encryption Set',    type:'IAM',        service:'azurerm_disk_encryption_set',     icon:'DES'},
    {id:'az_queue_storage',  name:'Queue Storage',          type:'QUEUE',      service:'azurerm_storage_queue',           icon:'QST'},
    {id:'az_table_storage',  name:'Table Storage',          type:'DATABASE',   service:'azurerm_storage_table',           icon:'TBL'},
    {id:'az_datalake',       name:'Data Lake Storage Gen2', type:'STORAGE',    service:'azurerm_storage_data_lake_gen2_filesystem', icon:'ADLS'},
    {id:'az_netappfiles',    name:'Azure NetApp Files',     type:'STORAGE',    service:'azurerm_netapp_volume',           icon:'ANF'},
    {id:'az_elasticsan',     name:'Elastic SAN',            type:'STORAGE',    service:'azurerm_elastic_san',             icon:'ESAN'},
    {id:'az_storagemover',   name:'Storage Mover',          type:'OTHER',      service:'azurerm_storage_mover',           icon:'SMV'},
    {id:'az_avere',          name:'Avere vFXT',             type:'STORAGE',    service:'avere_vfxt',                      icon:'AVR', legacy:true},
    {id:'az_importexport',   name:'Import/Export Service',  type:'OTHER',      service:'import_export_service',           icon:'IEX'},
  ]},

  {g: 'Databases', items: [
    {id:'az_sql',            name:'Azure SQL Database',     type:'DATABASE',   service:'azurerm_mssql_database',          icon:'SQL', aliases:['az_sql_old']},
    {id:'az_sql_server',     name:'Azure SQL Server',       type:'DATABASE',   service:'azurerm_mssql_server',            icon:'SQLS'},
    {id:'az_sql_mi',         name:'SQL Managed Instance',   type:'DATABASE',   service:'azurerm_mssql_managed_instance',  icon:'SQLMI'},
    {id:'az_sql_elastic',    name:'SQL Elastic Pool',       type:'DATABASE',   service:'azurerm_mssql_elasticpool',       icon:'SQLEP'},
    {id:'az_cosmosdb',       name:'Azure Cosmos DB',        type:'DATABASE',   service:'azurerm_cosmosdb_account',        icon:'COS', aliases:['az_cosmos']},
    {id:'az_postgres',       name:'Database for PostgreSQL',type:'DATABASE',   service:'azurerm_postgresql_flexible_server', icon:'PG'},
    {id:'az_postgres_single',name:'PostgreSQL Single Server',type:'DATABASE',  service:'azurerm_postgresql_server',       icon:'PGS', legacy:true},
    {id:'az_mysql',          name:'Database for MySQL',     type:'DATABASE',   service:'azurerm_mysql_flexible_server',   icon:'MYS'},
    {id:'az_mysql_single',   name:'MySQL Single Server',    type:'DATABASE',   service:'azurerm_mysql_server',            icon:'MYSS', legacy:true},
    {id:'az_mariadb',        name:'Database for MariaDB',   type:'DATABASE',   service:'azurerm_mariadb_server',          icon:'MDB', legacy:true},
    {id:'az_redis',          name:'Cache for Redis',        type:'CACHE',      service:'azurerm_redis_cache',             icon:'RDS'},
    {id:'az_redis_enterprise',name:'Redis Enterprise',      type:'CACHE',      service:'azurerm_redis_enterprise_cluster',icon:'RDE'},
    {id:'az_cassandra',      name:'Managed Instance for Cassandra',type:'DATABASE',service:'azurerm_cosmosdb_cassandra_cluster', icon:'CAS'},
    {id:'az_sql_edge',       name:'Azure SQL Edge',         type:'DATABASE',   service:'sql_edge',                        icon:'SQLE'},
    {id:'az_sql_vm',         name:'SQL Server on Azure VM', type:'DATABASE',   service:'azurerm_mssql_virtual_machine',   icon:'SQLVM'},
    {id:'az_stretch_db',     name:'SQL Server Stretch DB',  type:'DATABASE',   service:'stretch_database',                icon:'STR', legacy:true},
  ]},

  {g: 'Networking', items: [
    {id:'az_vnet',           name:'Virtual Network',        type:'NETWORK',    service:'azurerm_virtual_network',         icon:'VNET'},
    {id:'az_subnet',         name:'Subnet',                 type:'NETWORK',    service:'azurerm_subnet',                  icon:'SUB'},
    {id:'az_nsg',            name:'Network Security Group', type:'NETWORK',    service:'azurerm_network_security_group',  icon:'NSG', extraCats:['security']},
    {id:'az_asg',            name:'Application Security Group',type:'NETWORK', service:'azurerm_application_security_group', icon:'ASG'},
    {id:'az_lb',             name:'Load Balancer',          type:'GATEWAY',    service:'azurerm_lb',                      icon:'LB'},
    {id:'az_appgw',          name:'Application Gateway',    type:'GATEWAY',    service:'azurerm_application_gateway',     icon:'AGW'},
    {id:'az_waf_policy',     name:'WAF Policy',             type:'NETWORK',    service:'azurerm_web_application_firewall_policy', icon:'WAF', extraCats:['security']},
    {id:'az_vpngw',          name:'VPN Gateway',            type:'NETWORK',    service:'azurerm_virtual_network_gateway', icon:'VPNG'},
    {id:'az_er',             name:'ExpressRoute',           type:'NETWORK',    service:'azurerm_express_route_circuit',   icon:'ER'},
    {id:'az_er_direct',      name:'ExpressRoute Direct',    type:'NETWORK',    service:'azurerm_express_route_port',      icon:'ERD'},
    {id:'az_firewall',       name:'Azure Firewall',         type:'NETWORK',    service:'azurerm_firewall',                icon:'AFW', extraCats:['security']},
    {id:'az_firewall_policy',name:'Firewall Policy',        type:'NETWORK',    service:'azurerm_firewall_policy',         icon:'AFP', extraCats:['security']},
    {id:'az_frontdoor',      name:'Front Door',             type:'CDN',        service:'azurerm_cdn_frontdoor_profile',   icon:'AFD'},
    {id:'az_cdn',            name:'Content Delivery Network',type:'CDN',       service:'azurerm_cdn_endpoint',            icon:'CDN'},
    {id:'az_dns',            name:'DNS Zone',               type:'NETWORK',    service:'azurerm_dns_zone',                icon:'DNS'},
    {id:'az_private_dns',    name:'Private DNS Zone',       type:'NETWORK',    service:'azurerm_private_dns_zone',        icon:'PDNS'},
    {id:'az_trafficmgr',     name:'Traffic Manager',        type:'NETWORK',    service:'azurerm_traffic_manager_profile', icon:'TM'},
    {id:'az_vwan',           name:'Virtual WAN',            type:'NETWORK',    service:'azurerm_virtual_wan',             icon:'VWAN'},
    {id:'az_netwatcher',     name:'Network Watcher',        type:'MONITORING', service:'azurerm_network_watcher',         icon:'NW'},
    {id:'az_privatelink',    name:'Private Link / Endpoint',type:'NETWORK',    service:'azurerm_private_endpoint',        icon:'PL'},
    {id:'az_natgw',          name:'NAT Gateway',            type:'NETWORK',    service:'azurerm_nat_gateway',             icon:'NAT'},
    {id:'az_route_server',   name:'Route Server',           type:'NETWORK',    service:'azurerm_route_server',            icon:'RS'},
    {id:'az_ddos',           name:'DDoS Protection',        type:'NETWORK',    service:'azurerm_network_ddos_protection_plan', icon:'DDOS', extraCats:['security']},
    {id:'az_bastion',        name:'Azure Bastion',          type:'NETWORK',    service:'azurerm_bastion_host',            icon:'BAS', extraCats:['security']},
    {id:'az_peering_service',name:'Peering Service',        type:'NETWORK',    service:'azurerm_peering_service',         icon:'PRS'},
    {id:'az_vnet_manager',   name:'Virtual Network Manager',type:'NETWORK',    service:'azurerm_network_manager',         icon:'VNM'},
    {id:'az_public_ip',      name:'Public IP',              type:'NETWORK',    service:'azurerm_public_ip',               icon:'PIP'},
  ]},

  {g: 'Web', items: [
    {id:'az_appservice',     name:'App Service (Web App)',  type:'COMPUTE',    service:'azurerm_linux_web_app',           icon:'APS'},
    {id:'az_appservice_plan',name:'App Service Plan',       type:'COMPUTE',    service:'azurerm_service_plan',            icon:'ASP'},
    {id:'az_staticwebapp',   name:'Static Web Apps',        type:'SERVERLESS', service:'azurerm_static_web_app',          icon:'SWA'},
    {id:'az_appconfig',      name:'App Configuration',      type:'IAM',        service:'azurerm_app_configuration',       icon:'APC'},
    {id:'az_signalr',        name:'SignalR Service',        type:'GATEWAY',    service:'azurerm_signalr_service',         icon:'SIG'},
    {id:'az_webpubsub',      name:'Web PubSub',             type:'GATEWAY',    service:'azurerm_web_pubsub',              icon:'WPS'},
    {id:'az_appcert',        name:'App Service Certificates',type:'IAM',       service:'azurerm_app_service_certificate', icon:'CERT'},
  ]},

  {g: 'Mobile', items: [
    {id:'az_notificationhub',name:'Notification Hubs',      type:'QUEUE',      service:'azurerm_notification_hub',        icon:'NH'},
    {id:'az_maps',           name:'Azure Maps',             type:'SERVERLESS', service:'azurerm_maps_account',            icon:'MAP'},
    {id:'az_appcenter',      name:'App Center',             type:'OTHER',      service:'app_center',                      icon:'APC2', legacy:true},
  ]},

  {g: 'Analytics', items: [
    {id:'az_synapse',        name:'Synapse Analytics',      type:'DATABASE',   service:'azurerm_synapse_workspace',       icon:'SYN'},
    {id:'az_synapse_sqlpool',name:'Synapse Dedicated SQL Pool',type:'DATABASE',service:'azurerm_synapse_sql_pool',        icon:'SSQL'},
    {id:'az_synapse_spark',  name:'Synapse Spark Pool',     type:'COMPUTE',    service:'azurerm_synapse_spark_pool',      icon:'SPK'},
    {id:'az_databricks',     name:'Azure Databricks',       type:'COMPUTE',    service:'azurerm_databricks_workspace',    icon:'DBX'},
    {id:'az_hdinsight',      name:'HDInsight',               type:'COMPUTE',   service:'azurerm_hdinsight_hadoop_cluster',icon:'HDI'},
    {id:'az_datafactory',    name:'Data Factory',           type:'OTHER',      service:'azurerm_data_factory',            icon:'ADF'},
    {id:'az_streamanalytics',name:'Stream Analytics',       type:'COMPUTE',    service:'azurerm_stream_analytics_job',    icon:'STA'},
    {id:'az_powerbi_embedded',name:'Power BI Embedded',     type:'OTHER',      service:'azurerm_powerbi_embedded',        icon:'PBI'},
    {id:'az_dataexplorer',   name:'Data Explorer (Kusto)',  type:'DATABASE',   service:'azurerm_kusto_cluster',           icon:'ADX'},
    {id:'az_purview',        name:'Microsoft Purview',      type:'IAM',        service:'azurerm_purview_account',         icon:'PUR'},
    {id:'az_loganalytics',   name:'Log Analytics Workspace',type:'MONITORING', service:'azurerm_log_analytics_workspace', icon:'LAW', extraCats:['monitoring']},
    {id:'az_analysisservices',name:'Analysis Services',     type:'DATABASE',   service:'azurerm_analysis_services_server',icon:'AAS'},
    {id:'az_dla',            name:'Data Lake Analytics',    type:'COMPUTE',    service:'data_lake_analytics',             icon:'DLA', legacy:true},
    {id:'az_tsi',            name:'Time Series Insights',   type:'DATABASE',   service:'time_series_insights',            icon:'TSI', legacy:true},
  ]},

  {g: 'AI + Machine Learning', items: [
    {id:'az_openai',         name:'Azure OpenAI Service',   type:'GATEWAY',    service:'azurerm_cognitive_account',       icon:'AOAI', extraCats:['ai']},
    {id:'az_aifoundry',      name:'Azure AI Foundry',       type:'OTHER',      service:'azurerm_ai_foundry',              icon:'AIF',  extraCats:['ai']},
    {id:'az_ml',             name:'Azure Machine Learning', type:'COMPUTE',    service:'azurerm_machine_learning_workspace', icon:'AML', extraCats:['ai']},
    {id:'az_ml_compute',     name:'ML Compute Instance',    type:'COMPUTE',    service:'azurerm_machine_learning_compute_instance', icon:'MLC', extraCats:['ai']},
    {id:'az_cognitive',      name:'Azure AI Services',      type:'SERVERLESS', service:'azurerm_cognitive_account',       icon:'COG',  extraCats:['ai']},
    {id:'az_aisearch',       name:'Azure AI Search',        type:'GATEWAY',    service:'azurerm_search_service',          icon:'AIS',  extraCats:['ai']},
    {id:'az_botservice',     name:'Azure Bot Service',      type:'SERVERLESS', service:'azurerm_bot_service_azure_bot',   icon:'BOT',  extraCats:['ai']},
    {id:'az_videoindexer',   name:'AI Video Indexer',       type:'SERVERLESS', service:'azurerm_video_indexer_account',   icon:'AVI',  extraCats:['ai']},
    {id:'az_docintel',       name:'AI Document Intelligence',type:'SERVERLESS',service:'form_recognizer',                 icon:'DOCI', extraCats:['ai']},
    {id:'az_speech',         name:'AI Speech',              type:'SERVERLESS', service:'speech_service',                  icon:'SPCH', extraCats:['ai']},
    {id:'az_vision',         name:'AI Vision',              type:'SERVERLESS', service:'computer_vision',                 icon:'CVIS', extraCats:['ai']},
    {id:'az_language',       name:'AI Language',            type:'SERVERLESS', service:'language_service',                icon:'LANG', extraCats:['ai']},
    {id:'az_translator',     name:'AI Translator',          type:'SERVERLESS', service:'translator',                      icon:'TRL',  extraCats:['ai']},
    {id:'az_contentsafety',  name:'AI Content Safety',      type:'SERVERLESS', service:'content_safety',                  icon:'CSAF', extraCats:['ai']},
    {id:'az_customvision',   name:'Custom Vision',          type:'SERVERLESS', service:'custom_vision',                   icon:'CSV',  extraCats:['ai']},
    {id:'az_face',           name:'Face API',               type:'SERVERLESS', service:'face_api',                        icon:'FACE', extraCats:['ai']},
    {id:'az_healthbot',      name:'Health Bot',             type:'SERVERLESS', service:'health_bot',                      icon:'HBOT', extraCats:['ai']},
    {id:'az_immersivereader',name:'Immersive Reader',       type:'SERVERLESS', service:'immersive_reader',                icon:'IMR',  extraCats:['ai']},
    {id:'az_luis',           name:'LUIS',                   type:'SERVERLESS', service:'luis',                            icon:'LUIS', extraCats:['ai'], legacy:true},
    {id:'az_qnamaker',       name:'QnA Maker',              type:'SERVERLESS', service:'qna_maker',                       icon:'QNA',  extraCats:['ai'], legacy:true},
    {id:'az_anomaly',        name:'Anomaly Detector',       type:'SERVERLESS', service:'anomaly_detector',                icon:'AD2',  extraCats:['ai'], legacy:true},
    {id:'az_personalizer',   name:'Personalizer',           type:'SERVERLESS', service:'personalizer',                    icon:'PERS', extraCats:['ai'], legacy:true},
    {id:'az_contentmoderator',name:'Content Moderator',     type:'SERVERLESS', service:'content_moderator',               icon:'CMOD', extraCats:['ai'], legacy:true},
  ]},

  {g: 'Integration', items: [
    {id:'az_logicapps',      name:'Logic Apps',             type:'SERVERLESS', service:'azurerm_logic_app_workflow',      icon:'LA'},
    {id:'az_functions',      name:'Azure Functions',        type:'SERVERLESS', service:'azurerm_linux_function_app',      icon:'FN'},
    {id:'az_servicebus',     name:'Service Bus',            type:'QUEUE',      service:'azurerm_servicebus_namespace',    icon:'SB'},
    {id:'az_eventgrid',      name:'Event Grid',             type:'QUEUE',      service:'azurerm_eventgrid_topic',         icon:'EG'},
    {id:'az_eventhub',       name:'Event Hubs',             type:'QUEUE',      service:'azurerm_eventhub_namespace',      icon:'EH'},
    {id:'az_apim',           name:'API Management',         type:'GATEWAY',    service:'azurerm_api_management',          icon:'APIM'},
    {id:'az_relay',          name:'Azure Relay',            type:'NETWORK',    service:'azurerm_relay_namespace',         icon:'REL'},
    {id:'az_datashare',      name:'Data Share',             type:'OTHER',      service:'azurerm_data_share_account',      icon:'DSH'},
  ]},

  {g: 'Internet of Things', items: [
    {id:'az_iothub',         name:'IoT Hub',                 type:'GATEWAY',   service:'azurerm_iothub',                  icon:'IOTH', extraCats:['embedded']},
    {id:'az_iotcentral',     name:'IoT Central',             type:'GATEWAY',   service:'azurerm_iotcentral_application',  icon:'IOTC', extraCats:['embedded']},
    {id:'az_iotedge',        name:'IoT Edge',                type:'COMPUTE',   service:'azurerm_iothub_endpoint',         icon:'IOTE', extraCats:['embedded']},
    {id:'az_dps',            name:'Device Provisioning Service',type:'GATEWAY',service:'azurerm_iothub_dps',              icon:'DPS',  extraCats:['embedded']},
    {id:'az_digitaltwins',   name:'Digital Twins',           type:'DATABASE',  service:'azurerm_digital_twins_instance',  icon:'DGT',  extraCats:['embedded']},
    {id:'az_sphere',         name:'Azure Sphere',            type:'COMPUTE',   service:'azurerm_sphere_catalog',          icon:'SPH',  extraCats:['embedded']},
    {id:'az_rtos',           name:'Azure RTOS',              type:'OTHER',     service:'azure_rtos',                      icon:'RTOS', extraCats:['embedded'], legacy:true},
  ]},

  {g: 'Identity', items: [
    {id:'az_entraid',        name:'Microsoft Entra ID',     type:'IAM',        service:'azuread_user',                    icon:'EID', extraCats:['security'], aliases:['az_iam']},
    {id:'az_entra_b2c',      name:'Entra ID B2C',           type:'IAM',        service:'azurerm_aadb2c_directory',        icon:'B2C', extraCats:['security']},
    {id:'az_managed_identity',name:'Managed Identity',      type:'IAM',        service:'azurerm_user_assigned_identity',  icon:'MID', extraCats:['security']},
    {id:'az_aadds',          name:'Entra Domain Services',  type:'IAM',        service:'azurerm_active_directory_domain_service', icon:'ADDS', extraCats:['security']},
    {id:'az_pim',            name:'Privileged Identity Mgmt',type:'IAM',       service:'azuread_privileged_access_group_assignment_schedule', icon:'PIM', extraCats:['security']},
    {id:'az_conditional_access',name:'Conditional Access',  type:'IAM',        service:'azuread_conditional_access_policy', icon:'CA', extraCats:['security']},
    {id:'az_verified_id',    name:'Entra Verified ID',      type:'IAM',        service:'entra_verified_id',                icon:'VID', extraCats:['security']},
    {id:'az_workload_id',    name:'Entra Workload ID',      type:'IAM',        service:'azuread_application_federated_identity_credential', icon:'WID', extraCats:['security']},
    {id:'az_permissions_mgmt',name:'Entra Permissions Mgmt',type:'IAM',        service:'entra_permissions_management',     icon:'EPM', extraCats:['security']},
  ]},

  {g: 'Security', items: [
    {id:'az_keyvault',       name:'Key Vault',               type:'IAM',       service:'azurerm_key_vault',                icon:'KV', extraCats:['security']},
    {id:'az_managed_hsm',    name:'Managed HSM',             type:'IAM',       service:'azurerm_key_vault_managed_hardware_security_module', icon:'MHSM', extraCats:['security']},
    {id:'az_dedicated_hsm',  name:'Dedicated HSM',           type:'IAM',       service:'azurerm_dedicated_hardware_security_module', icon:'DHSM', extraCats:['security']},
    {id:'az_defender_cloud', name:'Microsoft Defender for Cloud',type:'MONITORING',service:'azurerm_security_center_subscription_pricing', icon:'MDC', extraCats:['security']},
    {id:'az_sentinel',       name:'Microsoft Sentinel',      type:'MONITORING',service:'azurerm_sentinel_log_analytics_workspace_onboarding', icon:'SEN', extraCats:['security']},
    {id:'az_attestation',    name:'Azure Attestation',       type:'IAM',       service:'azurerm_attestation_provider',     icon:'ATT', extraCats:['security']},
    {id:'az_confidential_vm',name:'Confidential VMs',        type:'COMPUTE',   service:'confidential_vm',                  icon:'CVM', extraCats:['security']},
    {id:'az_defender_iot',   name:'Defender for IoT',        type:'MONITORING',service:'azurerm_iot_security_solution',    icon:'DIOT', extraCats:['security','embedded']},
    {id:'az_jit',            name:'Just-in-Time VM Access',  type:'IAM',       service:'just_in_time_vm_access',           icon:'JIT', extraCats:['security']},
    {id:'az_info_protection',name:'Purview Information Protection',type:'IAM', service:'purview_information_protection',   icon:'IP',  extraCats:['security']},
  ]},

  {g: 'Management and Governance', items: [
    {id:'az_monitor',        name:'Azure Monitor',           type:'MONITORING',service:'azurerm_monitor_diagnostic_setting', icon:'MON', extraCats:['monitoring']},
    {id:'az_appinsights',    name:'Application Insights',    type:'MONITORING',service:'azurerm_application_insights',     icon:'AI',  extraCats:['monitoring']},
    {id:'az_policy',         name:'Azure Policy',            type:'IAM',       service:'azurerm_policy_definition',        icon:'POL', extraCats:['security']},
    {id:'az_policy_assignment',name:'Policy Assignment',     type:'IAM',       service:'azurerm_subscription_policy_assignment', icon:'POLA', extraCats:['security']},
    {id:'az_blueprints',     name:'Azure Blueprints',        type:'OTHER',     service:'blueprints',                        icon:'BPR', legacy:true},
    {id:'az_costmgmt',       name:'Cost Management',         type:'MONITORING',service:'azurerm_cost_management_export',   icon:'COST'},
    {id:'az_advisor',        name:'Azure Advisor',           type:'MONITORING',service:'advisor',                           icon:'ADV'},
    {id:'az_resourcegraph',  name:'Resource Graph',          type:'MONITORING',service:'resource_graph',                    icon:'ARG'},
    {id:'az_automation',     name:'Azure Automation',        type:'OTHER',     service:'azurerm_automation_account',       icon:'AA'},
    {id:'az_update_manager',  name:'Azure Update Manager',   type:'OTHER',     service:'azurerm_maintenance_configuration', icon:'UM'},
    {id:'az_lighthouse',     name:'Azure Lighthouse',        type:'IAM',       service:'azurerm_lighthouse_definition',    icon:'LH'},
    {id:'az_managed_app',    name:'Managed Applications',    type:'OTHER',     service:'azurerm_managed_application',      icon:'MAPP'},
    {id:'az_arm_template',   name:'ARM Templates / Bicep',   type:'OTHER',     service:'azurerm_resource_group_template_deployment', icon:'ARM'},
    {id:'az_svchealth',      name:'Service Health',          type:'MONITORING',service:'service_health',                    icon:'SVH'},
    {id:'az_mgmt_group',     name:'Management Groups',       type:'IAM',       service:'azurerm_management_group',         icon:'MGG'},
    {id:'az_backup',         name:'Azure Backup',            type:'STORAGE',   service:'azurerm_backup_policy_vm',         icon:'BKP'},
    {id:'az_siterecovery',   name:'Azure Site Recovery',     type:'STORAGE',   service:'azurerm_site_recovery_replication_policy', icon:'ASR'},
    {id:'az_workbooks',      name:'Monitor Workbooks',       type:'MONITORING',service:'azurerm_application_insights_workbook', icon:'WBK', extraCats:['monitoring']},
    {id:'az_scheduler',      name:'Scheduler',               type:'OTHER',     service:'scheduler',                         icon:'SCH', legacy:true},
  ]},

  {g: 'Migration', items: [
    {id:'az_migrate',        name:'Azure Migrate',           type:'OTHER',     service:'azure_migrate',                     icon:'MIG'},
    {id:'az_dms',            name:'Database Migration Service',type:'OTHER',   service:'azurerm_database_migration_service',icon:'DMS'},
    {id:'az_databox',        name:'Data Box',                type:'STORAGE',   service:'data_box',                          icon:'DBX2'},
    {id:'az_databox_edge',   name:'Data Box Edge / Gateway',  type:'STORAGE',  service:'azurerm_databox_edge_device',       icon:'DBE'},
    {id:'az_migration_assistant',name:'App Service Migration Assistant',type:'OTHER',service:'app_service_migration_assistant',icon:'ASM'},
  ]},

  {g: 'Hybrid + Multicloud', items: [
    {id:'az_arc_servers',    name:'Arc-enabled Servers',     type:'COMPUTE',   service:'azurerm_arc_machine',              icon:'ARCS'},
    {id:'az_arc_data',       name:'Arc-enabled Data Services',type:'DATABASE', service:'azurerm_arc_kubernetes_cluster_extension', icon:'ARCD'},
    {id:'az_stack_hci',      name:'Azure Stack HCI',         type:'COMPUTE',   service:'azurerm_stack_hci_cluster',        icon:'HCI'},
    {id:'az_stack_hub',      name:'Azure Stack Hub',         type:'COMPUTE',   service:'azure_stack_hub',                   icon:'ASH'},
    {id:'az_stack_edge',     name:'Azure Stack Edge',        type:'COMPUTE',   service:'azure_stack_edge',                  icon:'ASE'},
    {id:'az_operator_nexus', name:'Operator Nexus',          type:'COMPUTE',   service:'azurerm_mobile_network',            icon:'NEX'},
  ]},

  {g: 'Developer Tools', items: [
    {id:'az_devops',         name:'Azure DevOps',            type:'OTHER',     service:'azuredevops_project',              icon:'ADO', extraCats:['cicd']},
    {id:'az_devops_pipelines',name:'Azure Pipelines',        type:'OTHER',     service:'azuredevops_build_definition',     icon:'APL', extraCats:['cicd']},
    {id:'az_devops_repos',   name:'Azure Repos',             type:'OTHER',     service:'azuredevops_git_repository',       icon:'ARP', extraCats:['cicd']},
    {id:'az_devops_boards',  name:'Azure Boards',            type:'OTHER',     service:'azuredevops_workitem',             icon:'ABD'},
    {id:'az_devops_artifacts',name:'Azure Artifacts',        type:'STORAGE',   service:'azuredevops_feed',                 icon:'AAR', extraCats:['cicd']},
    {id:'az_devbox',         name:'Microsoft Dev Box',       type:'COMPUTE',   service:'azurerm_dev_center_project',       icon:'DBOX'},
    {id:'az_deployment_env', name:'Deployment Environments', type:'OTHER',     service:'azurerm_dev_center_environment_type', icon:'DEE'},
    {id:'az_loadtesting',    name:'Azure Load Testing',      type:'OTHER',     service:'azurerm_load_test',                icon:'ALT'},
    {id:'az_chaos',          name:'Chaos Studio',            type:'OTHER',     service:'azurerm_chaos_studio_experiment',  icon:'CHS'},
    {id:'az_cli',            name:'Azure CLI',               type:'OTHER',     service:'azure_cli',                         icon:'CLI', extraCats:['cicd']},
  ]},

  {g: 'Media', items: [
    {id:'az_mediaservices',  name:'Media Services',          type:'COMPUTE',   service:'azurerm_media_services_account',   icon:'MS', legacy:true},
    {id:'az_commservices',   name:'Communication Services',  type:'GATEWAY',   service:'azurerm_communication_service',    icon:'ACS'},
  ]},

  {g: 'Mixed Reality', items: [
    {id:'az_remote_rendering',name:'Remote Rendering',       type:'COMPUTE',   service:'remote_rendering',                  icon:'ARR', legacy:true},
    {id:'az_spatial_anchors',name:'Spatial Anchors',         type:'OTHER',     service:'spatial_anchors',                   icon:'ASA', legacy:true},
    {id:'az_object_anchors', name:'Object Anchors',          type:'OTHER',     service:'object_anchors',                    icon:'AOA', legacy:true},
  ]},

  {g: 'Blockchain', items: [
    {id:'az_blockchain',     name:'Azure Blockchain Service',type:'DATABASE',  service:'blockchain_service',                icon:'ABS', legacy:true},
    {id:'az_blockchain_workbench',name:'Blockchain Workbench',type:'OTHER',    service:'blockchain_workbench',              icon:'ABW', legacy:true},
  ]},

  {g: 'Quantum', items: [
    {id:'az_quantum',        name:'Azure Quantum',           type:'COMPUTE',   service:'azurerm_quantum_workspace',        icon:'QNT'},
  ]},

  {g: 'SAP on Azure', items: [
    {id:'az_sap_large_instance',name:'SAP HANA Large Instances',type:'COMPUTE',service:'sap_hana_large_instance',          icon:'SAP2'},
    {id:'az_sap_center',     name:'Azure Center for SAP Solutions',type:'OTHER',service:'azurerm_workloads_sap_virtual_instance',icon:'ACSS'},
    {id:'az_rise_sap',       name:'RISE with SAP',           type:'OTHER',     service:'rise_with_sap',                     icon:'RISE'},
  ]},

  {g: 'Customer Enablement', items: [
    {id:'az_support',        name:'Azure Support Plans',     type:'OTHER',     service:'support_plans',                     icon:'SUP'},
    {id:'az_marketplace',    name:'Azure Marketplace',       type:'OTHER',     service:'azure_marketplace',                 icon:'MKT'},
    {id:'az_quickstart',     name:'Azure Quickstart Center',type:'OTHER',      service:'quickstart_center',                 icon:'QSC'},
  ]},

  {g: 'Virtual Desktop & End User Computing', items: [
    {id:'az_avd',            name:'Azure Virtual Desktop',   type:'COMPUTE',   service:'azurerm_virtual_desktop_host_pool', icon:'AVD'},
    {id:'az_avd_workspace',  name:'AVD Workspace',           type:'COMPUTE',   service:'azurerm_virtual_desktop_workspace', icon:'AVDW'},
    {id:'az_avd_appgroup',   name:'AVD Application Group',   type:'COMPUTE',   service:'azurerm_virtual_desktop_application_group', icon:'AVDA'},
  ]},
];

window.AZURE_CATALOG = AZURE_PRODUCTS.flatMap(({g, items}) =>
  items.map(item => ({provider: 'azure', cat: 'azure', group: g, ...item}))
);
