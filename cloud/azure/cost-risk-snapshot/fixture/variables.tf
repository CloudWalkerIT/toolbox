variable "subscription_id" {
  description = "Throwaway subscription to create the fixture in."
  type        = string
}

variable "location" {
  description = "Azure region."
  type        = string
  default     = "eastus2"
}

variable "prefix" {
  description = "Name prefix for fixture resources."
  type        = string
  default     = "crsfx"
}

variable "vm_size" {
  description = "Size for the Windows Server 2016 VM. It is deallocated after apply."
  type        = string
  default     = "Standard_B2s"
}

variable "create_empty_app_service_plan" {
  description = "Create an App Service plan with no apps. Needs App Service quota for app_service_plan_sku."
  type        = bool
  default     = false
}

variable "app_service_plan_sku" {
  description = "SKU for the empty plan. F1 is free but often has zero quota; B1 costs about $13/month."
  type        = string
  default     = "F1"
}
