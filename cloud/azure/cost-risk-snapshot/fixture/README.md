# Test fixture

A small, deliberately misconfigured environment for exercising
`azure-cost-risk-snapshot` against real Azure APIs. Every resource exists to
trip one check:

| Resource | Expected finding |
|---|---|
| Unattached managed disk | waste: `unattached_disk` |
| Unattached Standard public IP | waste: `unattached_public_ip` |
| NIC not attached to a VM | waste: `orphaned_nic` |
| Windows Server 2016 VM, deallocated | end_of_support (ends 2027-01-12), waste: `deallocated_vm` |
| NSG allowing 3389 from Internet | security: high |
| Storage account with public blob access allowed and shared key on | security: medium and low |
| Key Vault without purge protection | security: medium |
| Linux App Service plan with no apps (optional, off by default) | waste: `empty_app_service_plan` |

The empty App Service plan is off by default because many subscriptions have
no Free (F1) quota. Turn it on with `-var create_empty_app_service_plan=true`
(and `-var app_service_plan_sku=B1` if F1 quota is zero; about $13/month).

Not covered: snapshots older than 90 days (can't be created old), load balancers
with no backend (Standard LB costs money idling), SQL and Arc resources, and
storage minimum TLS below 1.2 (Azure Storage no longer accepts it).

**Cost:** a few dollars a week, mostly the deallocated VM's OS disk and the
public IP. Cost Management data appears after about 24 hours, and Advisor
recommendations after 24–48 hours.

## Use

Only against a subscription you can throw away.

```
terraform init
terraform apply -var subscription_id=<sub-id>
az vm deallocate -g "$(terraform output -raw resource_group)" -n "$(terraform output -raw vm_name)"
azure-cost-risk-snapshot -s <sub-id>
terraform destroy -var subscription_id=<sub-id>
```

The VM admin password is random and never output. Nothing listens on the
internet: the VM has no public IP, and the open NSG is not attached to anything.
