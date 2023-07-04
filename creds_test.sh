#!/bin/bash

# Specify the AWS region
region='eu-west-1'

# Specify the role ARN
role_arn='arn:aws:iam::673443487762:role/TechMCrossAccountAutomation'

# Specify a session name
session_name='karthick-test'

# Assume the role and get temporary security credentials
credentials=$(aws sts assume-role --role-arn $role_arn --role-session-name $session_name --region $region)

# Extract the keys and token from the response
aws_access_key_id=$(echo $credentials | jq -r .Credentials.AccessKeyId)
aws_secret_access_key=$(echo $credentials | jq -r .Credentials.SecretAccessKey)
aws_session_token=$(echo $credentials | jq -r .Credentials.SessionToken)

owner_id=["580154993495"]

# List EC2 instances in the other account
AWS_ACCESS_KEY_ID=$aws_access_key_id AWS_SECRET_ACCESS_KEY=$aws_secret_access_key AWS_SESSION_TOKEN=$aws_session_token aws ec2 describe-instances --filters Name=owner-id,Values=$owner_id --query 'Reservations[*].Instances[*].InstanceId' --output text --region $region
