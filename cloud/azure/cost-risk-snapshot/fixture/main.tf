# Deliberately misconfigured test environment for azure-cost-risk-snapshot.
# Every resource here exists to trip one of the tool's checks. Apply it only to
# a throwaway subscription, run the tool, then destroy it.

terraform {
  required_version = ">= 1.6"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

provider "azurerm" {
  features {
    key_vault {
      purge_soft_delete_on_destroy = true
    }
    resource_group {
      prevent_deletion_if_contains_resources = false
    }
  }
  subscription_id = var.subscription_id
}

data "azurerm_client_config" "current" {}

resource "random_string" "suffix" {
  length  = 6
  upper   = false
  special = false
}

resource "random_password" "vm_admin" {
  length  = 24
  special = true
}

locals {
  name = "${var.prefix}-${random_string.suffix.result}"
  tags = {
    purpose = "cost-risk-snapshot-fixture"
    delete  = "after-test"
  }
}

resource "azurerm_resource_group" "fixture" {
  name     = "rg-${local.name}"
  location = var.location
  tags     = local.tags
}

resource "azurerm_virtual_network" "fixture" {
  name                = "vnet-${local.name}"
  location            = azurerm_resource_group.fixture.location
  resource_group_name = azurerm_resource_group.fixture.name
  address_space       = ["10.90.0.0/24"]
  tags                = local.tags
}

resource "azurerm_subnet" "fixture" {
  name                 = "snet-default"
  resource_group_name  = azurerm_resource_group.fixture.name
  virtual_network_name = azurerm_virtual_network.fixture.name
  address_prefixes     = ["10.90.0.0/26"]
}

# waste: unattached managed disk
resource "azurerm_managed_disk" "unattached" {
  name                 = "disk-unattached-${local.name}"
  location             = azurerm_resource_group.fixture.location
  resource_group_name  = azurerm_resource_group.fixture.name
  storage_account_type = "Standard_LRS"
  create_option        = "Empty"
  disk_size_gb         = 4
  tags                 = local.tags
}

# waste: unattached public IP
resource "azurerm_public_ip" "unattached" {
  name                = "pip-unattached-${local.name}"
  location            = azurerm_resource_group.fixture.location
  resource_group_name = azurerm_resource_group.fixture.name
  allocation_method   = "Static"
  sku                 = "Standard"
  tags                = local.tags
}

# waste: orphaned NIC (not attached to any VM)
resource "azurerm_network_interface" "orphan" {
  name                = "nic-orphan-${local.name}"
  location            = azurerm_resource_group.fixture.location
  resource_group_name = azurerm_resource_group.fixture.name
  tags                = local.tags

  ip_configuration {
    name                          = "ipconfig1"
    subnet_id                     = azurerm_subnet.fixture.id
    private_ip_address_allocation = "Dynamic"
  }
}

# security (high): RDP open to the internet
resource "azurerm_network_security_group" "open_rdp" {
  name                = "nsg-open-rdp-${local.name}"
  location            = azurerm_resource_group.fixture.location
  resource_group_name = azurerm_resource_group.fixture.name
  tags                = local.tags

  security_rule {
    name                       = "allow-rdp-internet"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "3389"
    source_address_prefix      = "Internet"
    destination_address_prefix = "*"
  }
}

# end of support: Windows Server 2016. No public IP, and the NSG above is not
# attached to it. Deallocate it after apply (see README) so it also shows up as
# a deallocated VM whose disk is still billed.
resource "azurerm_network_interface" "vm" {
  name                = "nic-vm-${local.name}"
  location            = azurerm_resource_group.fixture.location
  resource_group_name = azurerm_resource_group.fixture.name
  tags                = local.tags

  ip_configuration {
    name                          = "ipconfig1"
    subnet_id                     = azurerm_subnet.fixture.id
    private_ip_address_allocation = "Dynamic"
  }
}

resource "azurerm_windows_virtual_machine" "ws2016" {
  name                  = "vm-ws2016-${random_string.suffix.result}"
  computer_name         = "ws2016fixture"
  location              = azurerm_resource_group.fixture.location
  resource_group_name   = azurerm_resource_group.fixture.name
  size                  = var.vm_size
  admin_username        = "fixtureadmin"
  admin_password        = random_password.vm_admin.result
  network_interface_ids = [azurerm_network_interface.vm.id]
  tags                  = local.tags

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  # Tenant policies (Defender, guest configuration) often add a system-assigned
  # identity after creation. Ignore it so the fixture doesn't show drift.
  lifecycle {
    ignore_changes = [identity]
  }

  source_image_reference {
    publisher = "MicrosoftWindowsServer"
    offer     = "WindowsServer"
    sku       = "2016-Datacenter-smalldisk"
    version   = "latest"
  }
}

# security (medium): public blob access allowed, shared key enabled
resource "azurerm_storage_account" "loose" {
  name                            = "stfx${random_string.suffix.result}"
  location                        = azurerm_resource_group.fixture.location
  resource_group_name             = azurerm_resource_group.fixture.name
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  allow_nested_items_to_be_public = true
  shared_access_key_enabled       = true
  min_tls_version                 = "TLS1_2"
  tags                            = local.tags
}

# security (medium): Key Vault without purge protection
resource "azurerm_key_vault" "no_purge" {
  name                       = "kv-fx-${random_string.suffix.result}"
  location                   = azurerm_resource_group.fixture.location
  resource_group_name        = azurerm_resource_group.fixture.name
  tenant_id                  = data.azurerm_client_config.current.tenant_id
  sku_name                   = "standard"
  soft_delete_retention_days = 7
  purge_protection_enabled   = false
  rbac_authorization_enabled = true
  tags                       = local.tags
}

# waste: App Service plan with no apps. Off by default: many subscriptions have
# no Free (F1) quota, and a Basic plan costs about $13/month while it exists.
resource "azurerm_service_plan" "empty" {
  count = var.create_empty_app_service_plan ? 1 : 0

  name                = "asp-empty-${local.name}"
  location            = azurerm_resource_group.fixture.location
  resource_group_name = azurerm_resource_group.fixture.name
  os_type             = "Linux"
  sku_name            = var.app_service_plan_sku
  tags                = local.tags
}
