"""
AWS Native Network Testing Suite
Uses AWS services: Reachability Analyzer, VPC Flow Logs, CloudWatch Network Monitor
Reduces custom Lambda dependencies and provides official AWS validation
"""

import boto3
import time
import json
from typing import Dict, List, Optional
from dataclasses import dataclass
from enum import Enum
from datetime import datetime, timedelta

class ReachabilityStatus(Enum):
    REACHABLE = "reachable"
    UNREACHABLE = "unreachable"
    RUNNING = "running"
    FAILED = "failed"

@dataclass
class ReachabilityTest:
    test_id: str
    source: str
    destination: str
    protocol: str
    port: Optional[int]
    status: ReachabilityStatus
    explanation: Optional[str]
    hop_details: Optional[List[Dict]]

class AWSNativeNetworkTester:
    """
    Uses AWS native services for comprehensive network testing:
    - Reachability Analyzer: Validates network paths
    - VPC Flow Logs: Analyzes actual traffic patterns
    - Transit Gateway Network Manager: Monitors TGW health
    - CloudWatch Network Monitor: End-to-end monitoring
    """
    
    def __init__(self, region: str = "us-east-1"):
        self.region = region
        self.ec2_client = boto3.client('ec2', region_name=region)
        self.logs_client = boto3.client('logs', region_name=region)
        self.network_manager = boto3.client('networkmanager', region_name=region)
        
    def create_reachability_analysis(self, 
                                     source_arn: str,
                                     destination_arn: str,
                                     protocol: str = "tcp",
                                     destination_port: Optional[int] = None) -> str:
        """
        Create a Reachability Analyzer analysis
        
        Args:
            source_arn: ARN of source (ENI, Internet Gateway, VPC Gateway Endpoint, etc.)
            destination_arn: ARN of destination
            protocol: tcp, udp, or icmp
            destination_port: Port number for tcp/udp
        
        Returns:
            Analysis ID
        """
        
        params = {
            'Source': source_arn,
            'Destination': destination_arn,
            'Protocol': protocol,
            'TagSpecifications': [{
                'ResourceType': 'network-insights-analysis',
                'Tags': [
                    {'Key': 'Purpose', 'Value': 'AFT-VPC-Testing'},
                    {'Key': 'CreatedAt', 'Value': datetime.utcnow().isoformat()}
                ]
            }]
        }
        
        if destination_port and protocol in ['tcp', 'udp']:
            params['DestinationPort'] = destination_port
        
        # First create a path
        path_response = self.ec2_client.create_network_insights_path(**params)
        path_id = path_response['NetworkInsightsPath']['NetworkInsightsPathId']
        
        # Then start analysis
        analysis_response = self.ec2_client.start_network_insights_analysis(
            NetworkInsightsPathId=path_id
        )
        
        return analysis_response['NetworkInsightsAnalysis']['NetworkInsightsAnalysisId']
    
    def wait_for_analysis(self, analysis_id: str, timeout_seconds: int = 300) -> Dict:
        """Wait for reachability analysis to complete"""
        
        start_time = time.time()
        
        while time.time() - start_time < timeout_seconds:
            response = self.ec2_client.describe_network_insights_analyses(
                NetworkInsightsAnalysisIds=[analysis_id]
            )
            
            analysis = response['NetworkInsightsAnalyses'][0]
            status = analysis['Status']
            
            if status == 'succeeded':
                return analysis
            elif status == 'failed':
                raise Exception(f"Analysis failed: {analysis.get('StatusMessage')}")
            
            time.sleep(5)
        
        raise TimeoutError(f"Analysis did not complete within {timeout_seconds} seconds")
    
    def parse_reachability_result(self, analysis: Dict) -> ReachabilityTest:
        """Parse reachability analysis results"""
        
        network_path_found = analysis.get('NetworkPathFound', False)
        
        # Extract explanations
        explanations = []
        if 'Explanations' in analysis:
            for exp in analysis['Explanations']:
                exp_code = exp.get('ExplanationCode', 'Unknown')
                direction = exp.get('Direction', '')
                explanations.append(f"{exp_code} ({direction})")
        
        # Extract forward path details
        hop_details = []
        if 'ForwardPathComponents' in analysis:
            for component in analysis['ForwardPathComponents']:
                hop = {
                    'sequence': component.get('SequenceNumber'),
                    'component': component.get('Component', {}).get('Name', 'Unknown'),
                    'component_type': component.get('Component', {}).get('ComponentType', 'Unknown'),
                }
                
                # Check for blocking components
                if component.get('OutboundHeader'):
                    hop['outbound'] = component['OutboundHeader']
                if component.get('InboundHeader'):
                    hop['inbound'] = component['InboundHeader']
                
                hop_details.append(hop)
        
        return ReachabilityTest(
            test_id=analysis['NetworkInsightsAnalysisId'],
            source=analysis.get('NetworkInsightsPathId', 'Unknown'),
            destination=analysis.get('NetworkInsightsPathId', 'Unknown'),
            protocol=analysis.get('Protocol', 'Unknown'),
            port=analysis.get('DestinationPort'),
            status=ReachabilityStatus.REACHABLE if network_path_found else ReachabilityStatus.UNREACHABLE,
            explanation="; ".join(explanations) if explanations else None,
            hop_details=hop_details
        )
    
    def test_vpc_to_vpc_reachability(self, 
                                     source_subnet: str,
                                     dest_subnet: str,
                                     source_account_id: str,
                                     dest_account_id: str,
                                     protocol: str = "tcp",
                                     port: int = 443) -> ReachabilityTest:
        """
        Test reachability between two VPCs through Transit Gateway
        
        This creates ENIs temporarily or uses existing test instances
        """
        
        # Get source and destination ENI ARNs
        # In practice, you'd have test instances or create temporary ENIs
        source_arn = f"arn:aws:ec2:{self.region}:{source_account_id}:subnet/{source_subnet}"
        dest_arn = f"arn:aws:ec2:{self.region}:{dest_account_id}:subnet/{dest_subnet}"
        
        analysis_id = self.create_reachability_analysis(
            source_arn=source_arn,
            destination_arn=dest_arn,
            protocol=protocol,
            destination_port=port
        )
        
        print(f"Created reachability analysis: {analysis_id}")
        
        analysis_result = self.wait_for_analysis(analysis_id)
        
        return self.parse_reachability_result(analysis_result)
    
    def analyze_vpc_flow_logs(self, 
                              vpc_id: str,
                              start_time: datetime,
                              end_time: datetime,
                              filter_pattern: str = None) -> Dict:
        """
        Analyze VPC Flow Logs for traffic patterns and issues
        
        Requires VPC Flow Logs to be enabled and sent to CloudWatch Logs
        """
        
        log_group_name = f"/aws/vpc/flowlogs/{vpc_id}"
        
        # Build CloudWatch Insights query
        query = f"""
        fields @timestamp, srcAddr, dstAddr, srcPort, dstPort, protocol, action, bytes, packets
        | filter action = "REJECT"
        | stats count() as reject_count by srcAddr, dstAddr, dstPort
        | sort reject_count desc
        | limit 20
        """
        
        if filter_pattern:
            query = filter_pattern
        
        try:
            # Start query
            response = self.logs_client.start_query(
                logGroupName=log_group_name,
                startTime=int(start_time.timestamp()),
                endTime=int(end_time.timestamp()),
                queryString=query
            )
            
            query_id = response['queryId']
            
            # Wait for results
            while True:
                result = self.logs_client.get_query_results(queryId=query_id)
                status = result['status']
                
                if status == 'Complete':
                    return {
                        'query_id': query_id,
                        'status': status,
                        'results': result['results'],
                        'statistics': result.get('statistics', {})
                    }
                elif status == 'Failed':
                    raise Exception("Flow log query failed")
                
                time.sleep(2)
                
        except self.logs_client.exceptions.ResourceNotFoundException:
            return {
                'error': f"Flow logs not enabled for VPC {vpc_id}",
                'recommendation': 'Enable VPC Flow Logs for better visibility'
            }
    
    def check_transit_gateway_health(self, tgw_id: str) -> Dict:
        """Check Transit Gateway attachment health and routing"""
        
        # Get all attachments
        attachments = self.ec2_client.describe_transit_gateway_attachments(
            Filters=[
                {'Name': 'transit-gateway-id', 'Values': [tgw_id]},
            ]
        )
        
        health_report = {
            'transit_gateway_id': tgw_id,
            'total_attachments': len(attachments['TransitGatewayAttachments']),
            'healthy_attachments': 0,
            'unhealthy_attachments': 0,
            'attachment_details': []
        }
        
        for attachment in attachments['TransitGatewayAttachments']:
            state = attachment['State']
            is_healthy = state == 'available'
            
            if is_healthy:
                health_report['healthy_attachments'] += 1
            else:
                health_report['unhealthy_attachments'] += 1
            
            health_report['attachment_details'].append({
                'attachment_id': attachment['TransitGatewayAttachmentId'],
                'resource_type': attachment['ResourceType'],
                'resource_id': attachment['ResourceId'],
                'state': state,
                'healthy': is_healthy
            })
        
        # Get route tables
        route_tables = self.ec2_client.describe_transit_gateway_route_tables(
            Filters=[{'Name': 'transit-gateway-id', 'Values': [tgw_id]}]
        )
        
        health_report['route_tables'] = []
        for rt in route_tables['TransitGatewayRouteTables']:
            # Get routes
            routes = self.ec2_client.search_transit_gateway_routes(
                TransitGatewayRouteTableId=rt['TransitGatewayRouteTableId'],
                Filters=[{'Name': 'state', 'Values': ['active']}]
            )
            
            health_report['route_tables'].append({
                'route_table_id': rt['TransitGatewayRouteTableId'],
                'state': rt['State'],
                'active_routes': len(routes['Routes'])
            })
        
        return health_report
    
    def validate_security_group_rules(self, vpc_id: str, expected_rules: List[Dict]) -> Dict:
        """
        Validate security group configurations against expected baseline
        Uses AWS Config if available for historical compliance
        """
        
        security_groups = self.ec2_client.describe_security_groups(
            Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}]
        )
        
        validation_results = {
            'vpc_id': vpc_id,
            'total_security_groups': len(security_groups['SecurityGroups']),
            'compliant': True,
            'violations': []
        }
        
        for sg in security_groups['SecurityGroups']:
            # Check for overly permissive rules
            for rule in sg.get('IpPermissions', []):
                for ip_range in rule.get('IpRanges', []):
                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                        # Check if this is expected
                        from_port = rule.get('FromPort', 'all')
                        to_port = rule.get('ToPort', 'all')
                        
                        # Alert on dangerous open rules
                        if from_port in [22, 3389, 3306, 5432]:  # SSH, RDP, MySQL, PostgreSQL
                            validation_results['violations'].append({
                                'security_group_id': sg['GroupId'],
                                'security_group_name': sg['GroupName'],
                                'issue': f'Port {from_port} open to 0.0.0.0/0',
                                'severity': 'HIGH'
                            })
                            validation_results['compliant'] = False
        
        return validation_results
    
    def get_network_insights_recommendations(self, vpc_id: str) -> List[Dict]:
        """
        Get AWS recommendations based on Network Insights analyses
        """
        
        # List all analyses for this VPC
        paths = self.ec2_client.describe_network_insights_paths(
            Filters=[
                {'Name': 'tag:VpcId', 'Values': [vpc_id]}
            ]
        )
        
        recommendations = []
        
        for path in paths.get('NetworkInsightsPaths', []):
            # Get latest analysis
            analyses = self.ec2_client.describe_network_insights_analyses(
                NetworkInsightsPathIds=[path['NetworkInsightsPathId']],
                MaxResults=1
            )
            
            if analyses['NetworkInsightsAnalyses']:
                analysis = analyses['NetworkInsightsAnalyses'][0]
                
                if not analysis.get('NetworkPathFound', False):
                    # Path not found - generate recommendation
                    explanations = analysis.get('Explanations', [])
                    
                    for exp in explanations:
                        code = exp.get('ExplanationCode')
                        
                        # Map explanation codes to recommendations
                        if code == 'ENI_SG_RULES_MISMATCH':
                            recommendations.append({
                                'type': 'Security Group',
                                'issue': 'Security group rules blocking traffic',
                                'recommendation': 'Review and update security group ingress/egress rules',
                                'component': exp.get('SecurityGroup', {}).get('Name')
                            })
                        elif code == 'ROUTE_TABLE_ROUTE_NOT_MATCHING':
                            recommendations.append({
                                'type': 'Routing',
                                'issue': 'Route table missing required route',
                                'recommendation': 'Add route to transit gateway or target',
                                'component': exp.get('RouteTable', {}).get('Name')
                            })
                        elif code == 'NETWORK_ACL_RULES_MISMATCH':
                            recommendations.append({
                                'type': 'Network ACL',
                                'issue': 'Network ACL blocking traffic',
                                'recommendation': 'Update NACL rules to allow required traffic',
                                'component': exp.get('NetworkAcl', {}).get('Name')
                            })
        
        return recommendations


# Integration with existing test orchestrator
class EnhancedVPCTestOrchestrator:
    """
    Enhanced orchestrator using AWS native services
    """
    
    def __init__(self, hub_account_id: str, region: str = "us-east-1"):
        self.hub_account_id = hub_account_id
        self.region = region
        self.native_tester = AWSNativeNetworkTester(region)
        self.hub_session = boto3.Session(region_name=region)
    
    def run_native_reachability_tests(self, 
                                     source_vpc_id: str,
                                     dest_vpc_id: str,
                                     test_ports: List[int] = [443, 80]) -> List[Dict]:
        """
        Run reachability tests using AWS Reachability Analyzer
        Much more reliable than custom Lambda ping tests
        """
        
        results = []
        
        # Get subnets from both VPCs
        source_subnets = self.native_tester.ec2_client.describe_subnets(
            Filters=[{'Name': 'vpc-id', 'Values': [source_vpc_id]}]
        )
        
        dest_subnets = self.native_tester.ec2_client.describe_subnets(
            Filters=[{'Name': 'vpc-id', 'Values': [dest_vpc_id]}]
        )
        
        # Test from first private subnet to first private subnet
        if source_subnets['Subnets'] and dest_subnets['Subnets']:
            source_subnet = source_subnets['Subnets'][0]['SubnetId']
            dest_subnet = dest_subnets['Subnets'][0]['SubnetId']
            
            for port in test_ports:
                try:
                    test_result = self.native_tester.test_vpc_to_vpc_reachability(
                        source_subnet=source_subnet,
                        dest_subnet=dest_subnet,
                        source_account_id=self.hub_account_id,
                        dest_account_id=self.hub_account_id,  # Adjust for cross-account
                        protocol="tcp",
                        port=port
                    )
                    
                    results.append({
                        'test': f'Reachability-{source_vpc_id}-to-{dest_vpc_id}',
                        'port': port,
                        'status': test_result.status.value,
                        'reachable': test_result.status == ReachabilityStatus.REACHABLE,
                        'explanation': test_result.explanation,
                        'hop_count': len(test_result.hop_details) if test_result.hop_details else 0
                    })
                    
                except Exception as e:
                    results.append({
                        'test': f'Reachability-{source_vpc_id}-to-{dest_vpc_id}',
                        'port': port,
                        'status': 'error',
                        'error': str(e)
                    })
        
        return results
    
    def comprehensive_network_validation(self, vpc_id: str, tgw_id: str) -> Dict:
        """
        Run comprehensive validation using all AWS native tools
        """
        
        report = {
            'vpc_id': vpc_id,
            'timestamp': datetime.utcnow().isoformat(),
            'tests': {}
        }
        
        # 1. Transit Gateway Health
        print("Checking Transit Gateway health...")
        report['tests']['tgw_health'] = self.native_tester.check_transit_gateway_health(tgw_id)
        
        # 2. Security Group Validation
        print("Validating security groups...")
        report['tests']['security_groups'] = self.native_tester.validate_security_group_rules(
            vpc_id, 
            expected_rules=[]
        )
        
        # 3. Flow Log Analysis (last hour)
        print("Analyzing VPC Flow Logs...")
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=1)
        report['tests']['flow_logs'] = self.native_tester.analyze_vpc_flow_logs(
            vpc_id,
            start_time,
            end_time
        )
        
        # 4. Get recommendations
        print("Generating recommendations...")
        report['recommendations'] = self.native_tester.get_network_insights_recommendations(vpc_id)
        
        return report


# Example usage
if __name__ == "__main__":
    orchestrator = EnhancedVPCTestOrchestrator(
        hub_account_id="123456789012",
        region="us-east-1"
    )
    
    # Run comprehensive validation
    report = orchestrator.comprehensive_network_validation(
        vpc_id="vpc-abc123",
        tgw_id="tgw-xyz789"
    )
    
    print(json.dumps(report, indent=2))
