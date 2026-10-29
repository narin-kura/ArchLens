// Copyright (c) 2026 K.N.Narin (github.com/narin-kura). All rights reserved.
// Non-commercial use only. Commercial use requires written permission: github.com/narin-kura
// See LICENSE for full terms.
//
// ArchLens — Docker catalog for the interactive builder.
//
// Three kinds of entry, all provider 'docker':
//  - Compose objects: `service` is exactly what the Compose parser emits.
//  - Engine/Swarm objects: `service` is the real kreuzwerker/docker Terraform
//    resource type (the only ones the diagram's Terraform export writes).
//  - Docker products with no Terraform resource: listed so diagrams can show
//    them; their `service` is a descriptive id, never exported as Terraform.
const DOCKER_PRODUCTS = [
  {g: 'Compose', items: [
    {id:'docker_compose_service', name:'Compose Service',        type:'CONTAINER', service:'docker_compose_service', icon:'SVC'},
    {id:'docker_compose_volume',  name:'Compose Volume',         type:'STORAGE',   service:'docker_volume',          icon:'VOL'},
    {id:'docker_compose_network', name:'Compose Network',        type:'NETWORK',   service:'docker_network',         icon:'NET'},
    {id:'docker_compose_secret',  name:'Compose Secret',         type:'IAM',       service:'docker_compose_secret',  icon:'SEC'},
    {id:'docker_compose_config',  name:'Compose Config',         type:'OTHER',     service:'docker_compose_config',  icon:'CFG'},
    {id:'docker_dockerfile',      name:'Dockerfile (image build)', type:'CONTAINER', service:'dockerfile',           icon:'DF'},
  ]},

  {g: 'Engine & Swarm', items: [
    {id:'docker_container',       name:'Container',              type:'CONTAINER', service:'docker_container',       icon:'CTR'},
    {id:'docker_image',           name:'Image',                  type:'OTHER',     service:'docker_image',           icon:'IMG'},
    {id:'docker_tag',             name:'Image Tag',              type:'OTHER',     service:'docker_tag',             icon:'TAG'},
    {id:'docker_registry_image',  name:'Registry Image (push)',  type:'CONTAINER', service:'docker_registry_image',  icon:'PUSH'},
    {id:'docker_swarm_service',   name:'Swarm Service',          type:'CONTAINER', service:'docker_service',         icon:'SWS'},
    {id:'docker_swarm_secret',    name:'Swarm Secret',           type:'IAM',       service:'docker_secret',          icon:'SWX'},
    {id:'docker_swarm_config',    name:'Swarm Config',           type:'OTHER',     service:'docker_config',          icon:'SWC'},
    {id:'docker_plugin',          name:'Engine Plugin',          type:'OTHER',     service:'docker_plugin',          icon:'PLG'},
    {id:'docker_buildx_builder',  name:'Buildx Builder',         type:'COMPUTE',   service:'docker_buildx_builder',  icon:'BLDX'},
    {id:'docker_tf_compose',      name:'Compose Project (Terraform)', type:'CONTAINER', service:'docker_compose',    icon:'CMPS'},
    {id:'docker_engine_host',     name:'Docker Engine Host',     type:'COMPUTE',   service:'docker_engine_host',     icon:'ENG'},
    {id:'docker_swarm_cluster',   name:'Swarm Cluster',          type:'COMPUTE',   service:'docker_swarm_cluster',   icon:'SWM'},
  ]},

  {g: 'Registries & Supply Chain', items: [
    {id:'docker_hub_repository',  name:'Docker Hub Repository',  type:'CONTAINER', service:'docker_hub_repository',  icon:'HUB'},
    {id:'docker_distribution',    name:'Self-hosted Registry (Distribution)', type:'CONTAINER', service:'docker_distribution_registry', icon:'REG'},
    {id:'docker_scout',           name:'Docker Scout',           type:'MONITORING',service:'docker_scout',           icon:'SCT'},
    {id:'docker_hardened_images', name:'Docker Hardened Images', type:'CONTAINER', service:'docker_hardened_images', icon:'DHI'},
    {id:'docker_content_trust',   name:'Content Trust / Notary', type:'IAM',       service:'docker_content_trust',   icon:'DCT'},
  ]},

  {g: 'Developer Tools', items: [
    {id:'docker_build_cloud',     name:'Docker Build Cloud',     type:'COMPUTE',   service:'docker_build_cloud',     icon:'DBC'},
    {id:'docker_desktop',         name:'Docker Desktop',         type:'OTHER',     service:'docker_desktop',         icon:'DD'},
    {id:'docker_testcontainers',  name:'Testcontainers Cloud',   type:'COMPUTE',   service:'testcontainers_cloud',   icon:'TCC'},
  ]},
];

window.DOCKER_CATALOG = DOCKER_PRODUCTS.flatMap(({g, items}) =>
  items.map(item => ({provider: 'docker', cat: 'docker', group: g, ...item}))
);
