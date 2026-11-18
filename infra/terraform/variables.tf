variable "github_org" {
  description = "GitHub organization that owns the fleet"
  type        = string
  default     = "Triorex"
}

variable "platform_repo" {
  description = "Repository that holds the central reusable workflows"
  type        = string
  default     = "paved-road-platform"
}

variable "services" {
  description = "Services that get an ECR repository"
  type        = set(string)
  default     = ["payments-api", "orders-api"]
}

variable "tags" {
  type    = map(string)
  default = { owner = "platform", managed-by = "terraform", program = "paved-road" }
}
