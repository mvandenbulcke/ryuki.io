# Dry-run IaC for patch-maintenance offering.
#
# Uses only the built-in `terraform_data` resource (Terraform >= 1.4).
# No providers, no required_providers, no cloud calls.
# `terraform init` + `terraform plan` run fully offline.

variable "site" {
  description = "Target site for patch maintenance."
  type        = string
  default     = ""
}

variable "environment" {
  description = "Target environment for patch maintenance."
  type        = string
  default     = ""
}

variable "request_id" {
  description = "Request identifier (dry-run metadata only)."
  type        = string
  default     = ""
}

resource "terraform_data" "patch_maintenance_plan" {
  input = {
    site        = var.site
    environment = var.environment
    request_id  = var.request_id
  }
}

output "plan_summary" {
  description = "Dry-run plan summary for patch-maintenance."
  value       = "patch-maintenance dry-run plan: site=${var.site} env=${var.environment}"
}
