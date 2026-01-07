import boto3
import json
import time

class MultiAccountNetworkAudit:
    def __init__(self, network_account_id, region='us-east-1'):
        self.network_account_id = network_account_id
        self.region = region
        self.ec2_network = boto3.client('ec2', region_name=region)
        self.sts = boto3.client('sts')
        # Registry to track resources for guaranteed cleanup across accounts
        # Format: { 'account_id': [ 'eni-123', 'eni-456' ] }
        self.registry = {}

    def get_session(self, account_id):
        """Assumes the AFT Execution role in a spoke account."""
        role_arn = f"arn:aws:iam::{account_id}:role/AWSAFTExecution"
        response = self.sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName="NetworkAuditSession"
        )
        return boto3.Session(
            aws_access_key_id=response['Credentials']['AccessKeyId'],
            aws_secret_access_key=response['Credentials']['SecretAccessKey'],
            aws_session_token=response['Credentials']['SessionToken'],
            region_name=self.region
        )

    def create_cross_account_eni(self, account_id, subnet_id):
        session = self.get_session(account_id)
        ec2_spoke = session.client('ec2')
        
        print(f"--> Creating Probe in Account {account_id}, Subnet {subnet_id}")
        eni = ec2_spoke.create_network_interface(
            SubnetId=subnet_id,
            Description="TEMP-CROSS-ACCOUNT-PROBE"
        )['NetworkInterface']
        
        # Track for cleanup
        self.registry.setdefault(account_id, []).append(eni['NetworkInterfaceId'])
        return eni['NetworkInterfaceArn'] # Return ARN for cross-account pathing

    def run_analysis(self, src_eni_arn, dst_eni_arn, spoke_account_ids):
        # Create Path in the Network Account (Delegated Admin)
        path = self.ec2_network.create_network_insights_path(
            Source=src_eni_arn,
            Destination=dst_eni_arn,
            Protocol='tcp',
            DestinationPort=80
        )['NetworkInsightsPath']
        
        # Trigger Analysis including 'AdditionalAccounts' for the spokes
        analysis = self.ec2_network.start_network_insights_analysis(
            NetworkInsightsPathId=path['NetworkInsightsPathId'],
            AdditionalAccounts=spoke_account_ids
        )['NetworkInsightsAnalysis']
        
        return analysis['NetworkInsightsAnalysisId']

    def cleanup_all(self):
        print("\n--- Starting Global Cleanup ---")
        for account_id, eni_ids in self.registry.items():
            session = self.get_session(account_id)
            ec2_spoke = session.client('ec2')
            for eni_id in eni_ids:
                try:
                    ec2_spoke.delete_network_interface(NetworkInterfaceId=eni_id)
                    print(f"Deleted ENI {eni_id} in {account_id}")
                except Exception as e:
                    print(f"Failed to delete {eni_id}: {e}")

# --- Execution Logic (Simplified for AFT) ---
# 1. Parse Terraform state to find Account IDs and Subnet IDs
# 2. audit = MultiAccountNetworkAudit(network_account_id="111122223333")
# 3. src_arn = audit.create_cross_account_eni("ACCOUNT_A", "subnet-aaa")
# 4. dst_arn = audit.create_cross_account_eni("ACCOUNT_B", "subnet-bbb")
# 5. result = audit.run_analysis(src_arn, dst_arn, ["ACCOUNT_A", "ACCOUNT_B"])