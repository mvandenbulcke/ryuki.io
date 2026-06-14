# Dry-run IaC for linux-server-deployment offering.
#
# Uses only the built-in `terraform_data` resource (Terraform >= 1.4).
# No providers, no required_providers, no cloud calls.
# `terraform init` + `terraform plan` run fully offline.

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
  description = "Request identifier (dry-run metadata only)."
  type        = string
  default     = ""
}

resource "terraform_data" "linux_server_deployment_plan" {
  input = {
    site        = var.site
    environment = var.environment
    request_id  = var.request_id
  }
}

output "plan_summary" {
  description = "Dry-run plan summary for linux-server-deployment."
  value       = "linux-server-deployment dry-run plan: site=${var.site} env=${var.environment}"
}
