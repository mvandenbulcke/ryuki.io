# Real vSphere IaC for linux-server-deployment offering.
#
# Clones a Linux VM from a vSphere template using the vmware/vsphere provider.
# `terraform validate` passes fully offline (no vCenter connection — validate
# checks schema only). `terraform plan`/`apply` require a reachable vCenter and
# valid credentials; the dry-run runner uses validate as the offline correctness
# oracle and attempts plan best-effort.
#
# SECURITY: no credential VALUE is committed. The required vsphere provider
# arguments reference Terraform variables; the credential is injected at apply
# time as TF_VAR_vsphere_password (the runner's secret pipeline) — or, for a
# per-platform execution agent, via the provider-native VSPHERE_PASSWORD env var.
# `terraform validate` runs fully offline and needs no real values.

terraform {
  required_providers {
    vsphere = {
      source = "vmware/vsphere"
      # Exact pin keeps plan, apply, and out-of-band cleanup on one provider build.
      version = "2.16.1"
    }
  }
}

# ---------------------------------------------------------------------------
# Connection / authentication variables
# ---------------------------------------------------------------------------
# These satisfy the vsphere provider's required arguments. Endpoint and username
# carry non-secret placeholder defaults so `terraform validate` runs offline; the
# credential has NO default and is injected at apply time as TF_VAR_vsphere_password
# (fail-closed if absent).

variable "vsphere_server" {
  description = "vCenter server hostname or IP. Injected as TF_VAR_vsphere_server / VSPHERE_SERVER at apply time."
  type        = string
  default     = "vcenter.example.internal"
}

variable "vsphere_user" {
  description = "vCenter username. Injected as TF_VAR_vsphere_user / VSPHERE_USER at apply time."
  type        = string
  default     = "administrator@vsphere.local"
}

variable "vsphere_password" {
  description = "vCenter credential. Injected as TF_VAR_vsphere_password at apply time; never hardcoded."
  type        = string
  sensitive   = true
}

# ---------------------------------------------------------------------------
# Placement variables
# ---------------------------------------------------------------------------

variable "datacenter" {
  description = "vSphere datacenter name."
  type        = string

  validation {
    condition     = trimspace(var.datacenter) != ""
    error_message = "datacenter must name an explicit vSphere datacenter."
  }
}

variable "cluster" {
  description = "vSphere compute cluster name."
  type        = string

  validation {
    condition     = trimspace(var.cluster) != ""
    error_message = "cluster must name an explicit vSphere compute cluster."
  }
}

variable "datastore" {
  description = "vSphere datastore name."
  type        = string

  validation {
    condition     = trimspace(var.datastore) != ""
    error_message = "datastore must name an explicit vSphere datastore."
  }
}

variable "network" {
  description = "vSphere network (port group) name."
  type        = string

  validation {
    condition     = trimspace(var.network) != ""
    error_message = "network must name an explicit vSphere network."
  }
}

variable "template" {
  description = "Source VM template name to clone from."
  type        = string

  validation {
    condition     = trimspace(var.template) != ""
    error_message = "template must name an explicit source VM template."
  }
}

# ---------------------------------------------------------------------------
# VM configuration variables
# ---------------------------------------------------------------------------

variable "vm_name" {
  description = "Name for the deployed virtual machine."
  type        = string
  default     = "linux-vm-deploy"
}

variable "num_cpus" {
  description = "Number of vCPUs."
  type        = number
  default     = 2
}

variable "memory_mb" {
  description = "Memory in megabytes."
  type        = number
  default     = 4096
}

variable "disk_size_gb" {
  description = "OS disk size in gigabytes (thin-provisioned)."
  type        = number

  validation {
    condition     = var.disk_size_gb > 0
    error_message = "disk_size_gb must be greater than zero."
  }
}

# ---------------------------------------------------------------------------
# Request context variables (metadata; do not drive placement logic)
# ---------------------------------------------------------------------------

variable "site" {
  description = "Target site for linux-server-deployment."
  type        = string
  default     = ""
}

variable "environment" {
  description = "Target environment for linux-server-deployment."
  type        = string
  default     = ""
}

variable "request_id" {
  description = "Request identifier (metadata only)."
  type        = string
  default     = ""
}

# ---------------------------------------------------------------------------
# Provider
# ---------------------------------------------------------------------------
# The vsphere provider requires server/user/password arguments; each references
# a Terraform variable — no literal credential. At apply time the credential is
# supplied via TF_VAR_vsphere_password or the provider-native VSPHERE_PASSWORD
# env var. TLS verification stays on.

provider "vsphere" {
  vsphere_server       = var.vsphere_server
  user                 = var.vsphere_user
  password             = var.vsphere_password # secret-scan-allow: HCL variable reference, no literal credential
  allow_unverified_ssl = false
}

# ---------------------------------------------------------------------------
# Data sources — resolve placement identifiers
# ---------------------------------------------------------------------------

data "vsphere_datacenter" "dc" {
  name = var.datacenter
}

data "vsphere_compute_cluster" "cluster" {
  name          = var.cluster
  datacenter_id = data.vsphere_datacenter.dc.id
}

data "vsphere_datastore" "ds" {
  name          = var.datastore
  datacenter_id = data.vsphere_datacenter.dc.id
}

data "vsphere_network" "net" {
  name          = var.network
  datacenter_id = data.vsphere_datacenter.dc.id
}

data "vsphere_virtual_machine" "template" {
  name          = var.template
  datacenter_id = data.vsphere_datacenter.dc.id
}

# ---------------------------------------------------------------------------
# Resource — clone VM from template
# ---------------------------------------------------------------------------

resource "vsphere_virtual_machine" "linux_server" {
  name             = var.vm_name
  resource_pool_id = data.vsphere_compute_cluster.cluster.resource_pool_id
  datastore_id     = data.vsphere_datastore.ds.id

  num_cpus = var.num_cpus
  memory   = var.memory_mb

  guest_id = data.vsphere_virtual_machine.template.guest_id

  network_interface {
    network_id   = data.vsphere_network.net.id
    adapter_type = data.vsphere_virtual_machine.template.network_interface_types[0]
  }

  disk {
    label            = "disk0"
    size             = var.disk_size_gb
    thin_provisioned = true
  }

  clone {
    template_uuid = data.vsphere_virtual_machine.template.id
  }
}

# ---------------------------------------------------------------------------
# Outputs
# ---------------------------------------------------------------------------

output "vm_id" {
  description = "vSphere managed object ID of the deployed VM."
  value       = vsphere_virtual_machine.linux_server.id
}

output "plan_summary" {
  description = "Deployment plan summary for linux-server-deployment."
  value       = "linux-server-deployment: vm=${var.vm_name} site=${var.site} env=${var.environment}"
}
