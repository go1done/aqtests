import boto3
import json
import time
import sys

class MultiAccountAudit:
    def __init__(self, network_account_id, region='us-east-1'):
        self.network_account_id = network_account_id
        self.region = region
        self.ec2_network = boto3.client('ec2', region_name=region)
        self.sts = boto3.client('sts')
        # Format: { 'account_id': [ 'eni-id-1', 'eni-id-2' ] }
        self.cleanup_registry = {}

    def get_spoke_session(self, account_id):
        """Assume the AFT role in the spoke account."""
        role_arn = f"arn:aws:iam::{account_id}:role/AWSAFTExecution"
        creds = self.sts.assume_role(
            RoleArn=role_arn, RoleSessionName="NetAudit"
        )['Credentials']
        return boto3.Session(
            aws_access_key_id=creds['AccessKeyId'],
            aws_secret_access_key=creds['SecretAccessKey'],
            aws_session_token=creds['SessionToken'],
            region_name=self.region
        )

    def create_probe(self, account_id, subnet_id):
        session = self.get_spoke_session(account_id)
        ec2 = session.client('ec2')
        eni = ec2.create_network_interface(
            SubnetId=subnet_id, 
            Description="TEMP-PROBE-AFT"
        )['NetworkInterface']
        
        # Register for cleanup
        self.cleanup_registry.setdefault(account_id, []).append(eni['NetworkInterfaceId'])
        # Return ARN (Required for cross-account paths)
        return f"arn:aws:ec2:{self.region}:{account_id}:network-interface/{eni['NetworkInterfaceId']}"

    def run_validation(self, source_info, dest_info):
        """source_info: {'account': '123', 'subnet': 'sub-1'}"""
        try:
            src_arn = self.create_probe(source_info['account'], source_info['subnet'])
            dst_arn = self.create_probe(dest_info['account'], dest_info['subnet'])

            # 1. Create Path in Network Account
            path = self.ec2_network.create_network_insights_path(
                Source=src_arn, Destination=dst_arn, Protocol='tcp', DestinationPort=80
            )['NetworkInsightsPath']

            # 2. Trigger Cross-Account Analysis
            analysis = self.ec2_network.start_network_insights_analysis(
                NetworkInsightsPathId=path['NetworkInsightsPathId'],
                AdditionalAccounts=[source_info['account'], dest_info['account']]
            )['NetworkInsightsAnalysis']

            print(f"Analysis {analysis['NetworkInsightsAnalysisId']} started...")
            return self.wait_for_result(analysis['NetworkInsightsAnalysisId'])
        finally:
            self.cleanup()

    def wait_for_result(self, analysis_id):
        while True:
            res = self.ec2_network.describe_network_insights_analyses(
                NetworkInsightsAnalysisIds=[analysis_id]
            )['NetworkInsightsAnalyses'][0]
            if res['Status'] != 'running': return res
            time.sleep(5)

    def cleanup(self):
        for acc_id, enis in self.cleanup_registry.items():
            ec2 = self.get_spoke_session(acc_id).client('ec2')
            for eni_id in enis:
                try: ec2.delete_network_interface(NetworkInterfaceId=eni_id)
                except: pass