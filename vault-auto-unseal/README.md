# Terraform configuration for Vault on AWS with KMS unsealing

Terraform configuration for AWS or compatible clouds using KMS to unseal the vault cluster.

Consul is used for Vault storage and for cluster DNS (vault.service.consul)

## Customization

Create a `terraform.tfvars` file with details for your deployment, e.g.

    ami_id = "ami-06b4a86b6f16b47d0"
    ssh_key_name = "my-key"
    auto_unseal_kms_key_alias = "vault"
    
    subnet_tags = {
      vault_target = "yes"
    }
    
    vpc_tags = {
      vault_target = "yes"
    }

The AMI must contain the expected scripts to run vault and consul, as per:

  https://github.com/hashicorp/terraform-aws-vault/tree/master/examples/vault-consul-ami

The expected versions are:

* Consul 1.16.2
* Vault 1.15.0

on Ubuntu 22.04 or later.

The ssh key will be configured for SSH to all cluster instances from within the VPC.

A subnet and vpc must be tagged to identify them as targets for deployment use. It is expected that these are in a private
subnet with a NAT gateway, else you must configure allocation of a public ip for each instance.

If deploying on a non-aws cloud you may also need to set endpoint and instance type variables:

    endpoint_name_suffix = "-mysuffix"
    endpoint_url_suffix = "mydomain.com"
    
    vault_instance_type = "t3.small"
    consul_instance_type = "t3.small"

# Deployment

Use the usual terraform commands to create the infrastructure:

    terraform init
    terraform deploy

and then ssh to a vault instance and run:

    vault operator init

this will initialize and unseal all vault instances in the cluster.

    vault status

should show the unsealed status.
