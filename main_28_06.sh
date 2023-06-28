#!/bin/bash

# Get the instances with SSM patch compliance data
instance_ids=$(aws ec2 describe-instances --region us-west-2 --query 'Reservations[].Instances[].InstanceId' --output text)

# Print table header
printf "+%-17s+%-25s+%-15s+%-15s+%-20s+%-10s+%-25s+%-15s+%-20s+%-20s+%-30s+%-30s+%-30s+%-30s+%-30s+%-30s+\n" "-----------------" "-------------------------" "---------------" "---------------" "--------------------" "----------" "-------------------------" "---------------" "--------------------" "--------------------" "---------------------------" "---------------------------" "---------------------------" "---------------------------" "---------------------------" "---------------------------" >> output.txt
printf "|%-17s|%-25s|%-15s|%-15s|%-20s|%-10s|%-25s|%-15s|%-20s|%-20s|%-30s|%-30s|%-30s|%-30s|%-30s|%-30s|\n" "Instance ID" "Instance Name" "Instance IP" "Platform Name" "Platform Version" "SSM Version" "Patch Baseline" "Patch Group" "Compliance Status" "Compliance Severity" "Noncompliant Critical Count" "Noncompliant High Count" "Noncompliant Medium Count" "Noncompliant Low Count" "Noncompliant Informational Count" "Noncompliant Unspecified Count" >> output.txt
printf "+%-17s+%-25s+%-15s+%-15s+%-20s+%-10s+%-25s+%-15s+%-20s+%-20s+%-30s+%-30s+%-30s+%-30s+%-30s+%-30s+\n" "-----------------" "-------------------------" "---------------" "---------------" "--------------------" "----------" "-------------------------" "---------------" "--------------------" "--------------------" "---------------------------" "---------------------------" "---------------------------" "---------------------------" "---------------------------" "---------------------------" >> output.txt

# Iterate over each instance and retrieve data
for instance_id in $instance_ids; do
  instance_name=$(aws ec2 describe-instances --region us-west-2 --instance-ids $instance_id --query 'Reservations[].Instances[].Tags[?Key==`Name`].Value | [0]' --output text)
  instance_ip=$(aws ec2 describe-instances --region us-west-2 --instance-ids $instance_id --query 'Reservations[].Instances[].PrivateIpAddress' --output text)
  platform_name=$(aws ec2 describe-instances --region us-west-2 --instance-ids $instance_id --query 'Reservations[].Instances[].PlatformDetails' --output text)
  
  platform_version=$(aws ssm describe-instance-information --region us-west-2 --instance-information-filter-list key=InstanceIds,valueSet=$instance_id --query 'InstanceInformationList[].PlatformVersion' --output text)
  ssm_version=$(aws ssm describe-instance-information --region us-west-2 --instance-information-filter-list key=InstanceIds,valueSet=$instance_id --query 'InstanceInformationList[].AgentVersion' --output text)
  patch_baseline=$(aws ssm describe-instance-patch-states --region us-west-2 --instance-id $instance_id --query 'InstancePatchStates[].BaselineId' --output text)
  patch_group=$(aws ssm describe-instance-patch-states --region us-west-2 --instance-id $instance_id --query 'InstancePatchStates[].PatchGroup' --output text)
  
  # Get compliance status and write to a file
  aws ssm list-compliance-items --region us-west-2 --resource-ids $instance_id --query 'ComplianceItems[].Status' --output text > compliance_status.txt

  # Check compliance status
  if grep -q "NON_COMPLIANT" compliance_status.txt; then
    compliance_status="NON_COMPLIANT"
  else
    compliance_status="COMPLIANT"
  fi
  
  # Get compliance severity and write to a file
  aws ssm list-compliance-items --region us-west-2 --resource-ids $instance_id --query 'ComplianceItems[].Severity' --output text > compliance_severity.txt
  
  # Check compliance severity
  if grep -q "CRITICAL" compliance_severity.txt; then
    compliance_severity="CRITICAL"
  elif grep -q "UNSPECIFIED" compliance_severity.txt; then
    compliance_severity="UNSPECIFIED"
  else
    compliance_severity="UNSPECIFIED"
  fi

  # Get noncompliant patch counts
  noncompliant_critical_count=$(grep -o -w "CRITICAL" compliance_severity.txt | wc -l)
  noncompliant_high_count=$(grep -o -w "HIGH" compliance_severity.txt | wc -l)
  noncompliant_medium_count=$(grep -o -w "MEDIUM" compliance_severity.txt | wc -l)
  noncompliant_low_count=$(grep -o -w "LOW" compliance_severity.txt | wc -l)
  noncompliant_informational_count=$(grep -o -w "INFORMATIONAL" compliance_severity.txt | wc -l)
  noncompliant_unspecified_count=$(grep -o -w "UNSPECIFIED" compliance_severity.txt | wc -l)
  
  printf "|%-17s|%-25s|%-15s|%-15s|%-20s|%-10s|%-25s|%-15s|%-20s|%-20s|%-30s|%-30s|%-30s|%-30s|%-30s|%-30s|\n" "$instance_id" "$instance_name" "$instance_ip" "$platform_name" "$platform_version" "$ssm_version" "$patch_baseline" "$patch_group" "$compliance_status" "$compliance_severity" "$noncompliant_critical_count" "$noncompliant_high_count" "$noncompliant_medium_count" "$noncompliant_low_count" "$noncompliant_informational_count" "$noncompliant_unspecified_count" >> output.txt
  printf "+%-17s+%-25s+%-15s+%-15s+%-20s+%-10s+%-25s+%-15s+%-20s+%-20s+%-30s+%-30s+%-30s+%-30s+%-30s+%-30s+\n" "-----------------" "-------------------------" "---------------" "---------------" "--------------------" "----------" "-------------------------" "---------------" "--------------------" "--------------------" "---------------------------" "---------------------------" "---------------------------" "---------------------------" "---------------------------" "---------------------------" >> output.txt

done
