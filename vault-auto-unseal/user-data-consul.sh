#!/bin/bash
# This script is meant to be run in the User Data of each EC2 Instance while it's booting. The script uses the
# run-consul script to configure and start Consul in server mode. Note that this script assumes it's running in an AMI
# built from the Packer template in examples/vault-consul-ami/vault-consul.json.

set -e

# Send the log output from this script to user-data.log, syslog, and the console
# From: https://alestic.com/2010/12/ec2-user-data-output/
exec > >(tee /var/log/user-data.log|logger -t user-data -s 2>/dev/console) 2>&1

# Remove invalid consul configuration item, update script endpoints
sed --in-place '/disable_compat_1.9/d' /opt/consul/bin/run-consul
sed --in-place 's/aws ec2/aws ec2 --endpoint https:\/\/ec2${aws_endpoint_name_suffix}.${aws_region}.${aws_endpoint_url_suffix}/' /opt/consul/bin/run-consul
sed --in-place 's/aws autoscaling/aws autoscaling --endpoint https:\/\/autoscaling${aws_endpoint_name_suffix}.${aws_region}.${aws_endpoint_url_suffix}/' /opt/consul/bin/run-consul
sed --in-place 's/provider=aws/provider=aws endpoint=https:\/\/ec2${aws_endpoint_name_suffix}.${aws_region}.${aws_endpoint_url_suffix}/' /opt/consul/bin/run-consul

# These variables are passed in via Terraform template interpolation
/opt/consul/bin/run-consul --server --cluster-tag-key "${consul_cluster_tag_key}" --cluster-tag-value "${consul_cluster_tag_value}"
