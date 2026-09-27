output "resource_group" {
  value = azurerm_resource_group.fixture.name
}

output "vm_name" {
  value = azurerm_windows_virtual_machine.ws2016.name
}
