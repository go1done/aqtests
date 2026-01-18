"""
Enhanced Reachability Tester
Supports testing across different connection types:
- Transit Gateway
- VPC Peering
- VPN
- PrivateLink
"""

import boto3
from typing import Dict, Optional
from dataclasses import dataclass
from enum import Enum
import time

class ConnectionType(Enum):
    TRANSIT_GATEWAY = "tgw"
    VPC_PEERING = "pcx"
    VPN = "vpn"
    PRIVATELINK = "vpce"

class TestResult(Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARN"
    SKIP = "SKIP"

@dataclass
class TestCase:
    name: str
    result: TestResult
    message: str
    duration_ms: int
    metadata: Dict = None

class MultiConnectionReachabilityTester:
    """
    Reachability testing that adapts to connection type
    Uses appropriate AWS API for each connection type
    """
    
    def __init__(self, auth_config, region: str = "us-east-1"):
        self.auth = auth_config
        self.region = region
        self.hub_session = auth_config.get_hub_session()
        self.ec2 = self.hub_session.client('ec2')
    
    # =========================================================================
    # Transit Gateway Testing (existing implementation)
    # =========================================================================
    
    def test_tgw_reachability(self,
                             source_vpc: str,
                             dest_vpc: str,
                             tgw_id: str,
                             protocol: str = '-1',
                             port: int = None) -> TestCase:
        """Test reachability via Transit Gateway"""
        
        start_time = time.time()
        
        try:
            # Find TGW attachments
            source_arn = self._find_tgw_attachment_arn(source_vpc, tgw_id)
            dest_arn = self._find_tgw_attachment_arn(dest_vpc, tgw_id)
            
            if not source_arn or not dest_arn:
                return TestCase(
                    name=f"TGW-{protocol}:{port or 'all'}",
                    result=TestResult.SKIP,
                    message="TGW attachments not found",
                    duration_ms=int((time.time() - start_time) * 1000)
                )
            
            # Create and run analysis
            analysis_id = self._create_reachability_analysis(
                source_arn, dest_arn, protocol, port
            )
            
            result = self._wait_for_analysis(analysis_id)
            reachable = result.get('NetworkPathFound', False)
            
            return TestCase(
                name=f"TGW-{protocol}:{port or 'all'}",
                result=TestResult.PASS if reachable else TestResult.FAIL,
                message=f"Path {'found' if reachable else 'not found'}",
                duration_ms=int((time.time() - start_time) * 1000),
                metadata={'analysis_id': analysis_id, 'reachable': reachable}
            )
            
        except Exception as e:
            return TestCase(
                name=f"TGW-{protocol}:{port or 'all'}",
                result=TestResult.FAIL,
                message=f"Test error: {str(e)}",
                duration_ms=int((time.time() - start_time) * 1000)
            )
    
    # =========================================================================
    # VPC Peering Testing
    # =========================================================================
    
    def test_peering_reachability(self,
                                 source_vpc: str,
                                 dest_vpc: str,
                                 peering_id: str,
                                 protocol: str = '-1',
                                 port: int = None) -> TestCase:
        """
        Test reachability via VPC Peering
        
        For peering, we need ENIs in both VPCs
        Strategy: Use existing resources or create lightweight test endpoints
        """
        
        start_time = time.time()
        
        try:
            # Verify peering is active
            pcx = self.ec2.describe_vpc_peering_connections(
                VpcPeeringConnectionIds=[peering_id]
            )
            
            if not pcx['VpcPeeringConnections']:
                return TestCase(
                    name=f"Peering-{protocol}:{port or 'all'}",
                    result=TestResult.SKIP,
                    message=f"Peering {peering_id} not found",
                    duration_ms=int((time.time() - start_time) * 1000)
                )
            
            pcx_status = pcx['VpcPeeringConnections'][0]['Status']['Code']
            
            if pcx_status != 'active':
                return TestCase(
                    name=f"Peering-{protocol}:{port or 'all'}",
                    result=TestResult.FAIL,
                    message=f"Peering status: {pcx_status} (expected: active)",
                    duration_ms=int((time.time() - start_time) * 1000)
                )
            
            # Find or use existing ENIs in both VPCs
            source_eni = self._find_suitable_eni(source_vpc)
            dest_eni = self._find_suitable_eni(dest_vpc)
            
            if not source_eni or not dest_eni:
                return TestCase(
                    name=f"Peering-{protocol}:{port or 'all'}",
                    result=TestResult.WARN,
                    message="No suitable ENIs found for testing. Peering is active but cannot test reachability.",
                    duration_ms=int((time.time() - start_time) * 1000),
                    metadata={'peering_status': 'active', 'test_skipped': True}
                )
            
            # Create reachability analysis
            analysis_id = self._create_reachability_analysis(
                source_eni, dest_eni, protocol, port
            )
            
            result = self._wait_for_analysis(analysis_id)
            reachable = result.get('NetworkPathFound', False)
            
            return TestCase(
                name=f"Peering-{protocol}:{port or 'all'}",
                result=TestResult.PASS if reachable else TestResult.FAIL,
                message=f"Path {'found' if reachable else 'not found'} via peering {peering_id}",
                duration_ms=int((time.time() - start_time) * 1000),
                metadata={'analysis_id': analysis_id, 'reachable': reachable}
            )
            
        except Exception as e:
            return TestCase(
                name=f"Peering-{protocol}:{port or 'all'}",
                result=TestResult.FAIL,
                message=f"Test error: {str(e)}",
                duration_ms=int((time.time() - start_time) * 1000)
            )
    
    # =========================================================================
    # VPN Testing
    # =========================================================================
    
    def test_vpn_reachability(self,
                             vpc_id: str,
                             vpn_id: str,
                             protocol: str = '-1',
                             port: int = None) -> TestCase:
        """
        Test VPN connectivity
        
        VPN is harder to test with Reachability Analyzer
        We validate VPN tunnel status instead
        """
        
        start_time = time.time()
        
        try:
            vpn = self.ec2.describe_vpn_connections(
                VpnConnectionIds=[vpn_id]
            )
            
            if not vpn['VpnConnections']:
                return TestCase(
                    name=f"VPN-{protocol}:{port or 'all'}",
                    result=TestResult.SKIP,
                    message=f"VPN {vpn_id} not found",
                    duration_ms=int((time.time() - start_time) * 1000)
                )
            
            vpn_conn = vpn['VpnConnections'][0]
            state = vpn_conn['State']
            
            # Check tunnel status
            tunnels_up = 0
            total_tunnels = 0
            
            for options in vpn_conn.get('VgwTelemetry', []):
                total_tunnels += 1
                if options.get('Status') == 'UP':
                    tunnels_up += 1
            
            if state == 'available' and tunnels_up > 0:
                return TestCase(
                    name=f"VPN-Tunnel-Status",
                    result=TestResult.PASS,
                    message=f"VPN available, {tunnels_up}/{total_tunnels} tunnels UP",
                    duration_ms=int((time.time() - start_time) * 1000),
                    metadata={'tunnels_up': tunnels_up, 'total_tunnels': total_tunnels}
                )
            elif state == 'available':
                return TestCase(
                    name=f"VPN-Tunnel-Status",
                    result=TestResult.WARN,
                    message=f"VPN available but all tunnels DOWN",
                    duration_ms=int((time.time() - start_time) * 1000),
                    metadata={'tunnels_up': 0, 'total_tunnels': total_tunnels}
                )
            else:
                return TestCase(
                    name=f"VPN-Tunnel-Status",
                    result=TestResult.FAIL,
                    message=f"VPN state: {state}",
                    duration_ms=int((time.time() - start_time) * 1000)
                )
            
        except Exception as e:
            return TestCase(
                name=f"VPN-Tunnel-Status",
                result=TestResult.FAIL,
                message=f"Test error: {str(e)}",
                duration_ms=int((time.time() - start_time) * 1000)
            )
    
    # =========================================================================
    # PrivateLink Testing
    # =========================================================================
    
    def test_privatelink_reachability(self,
                                     vpc_id: str,
                                     endpoint_id: str,
                                     protocol: str = 'tcp',
                                     port: int = 443) -> TestCase:
        """Test VPC Endpoint connectivity"""
        
        start_time = time.time()
        
        try:
            endpoint = self.ec2.describe_vpc_endpoints(
                VpcEndpointIds=[endpoint_id]
            )
            
            if not endpoint['VpcEndpoints']:
                return TestCase(
                    name=f"PrivateLink-{protocol}:{port}",
                    result=TestResult.SKIP,
                    message=f"VPC Endpoint {endpoint_id} not found",
                    duration_ms=int((time.time() - start_time) * 1000)
                )
            
            ep = endpoint['VpcEndpoints'][0]
            state = ep['State']
            
            # Check endpoint status
            if state == 'available':
                # Count healthy network interfaces
                healthy_enis = len([
                    ni for ni in ep.get('NetworkInterfaceIds', [])
                ])
                
                return TestCase(
                    name=f"PrivateLink-{protocol}:{port}",
                    result=TestResult.PASS,
                    message=f"VPC Endpoint available with {healthy_enis} ENIs",
                    duration_ms=int((time.time() - start_time) * 1000),
                    metadata={'state': state, 'eni_count': healthy_enis}
                )
            else:
                return TestCase(
                    name=f"PrivateLink-{protocol}:{port}",
                    result=TestResult.FAIL,
                    message=f"VPC Endpoint state: {state}",
                    duration_ms=int((time.time() - start_time) * 1000)
                )
            
        except Exception as e:
            return TestCase(
                name=f"PrivateLink-{protocol}:{port}",
                result=TestResult.FAIL,
                message=f"Test error: {str(e)}",
                duration_ms=int((time.time() - start_time) * 1000)
            )
    
    # =========================================================================
    # Unified Testing Interface
    # =========================================================================
    
    def test_connectivity(self,
                         connection_type: ConnectionType,
                         source_vpc: str,
                         dest_vpc: str,
                         connection_id: str,
                         protocol: str = '-1',
                         port: int = None) -> TestCase:
        """
        Unified interface that dispatches to appropriate test method
        based on connection type
        """
        
        if connection_type == ConnectionType.TRANSIT_GATEWAY:
            return self.test_tgw_reachability(
                source_vpc, dest_vpc, connection_id, protocol, port
            )
        
        elif connection_type == ConnectionType.VPC_PEERING:
            return self.test_peering_reachability(
                source_vpc, dest_vpc, connection_id, protocol, port
            )
        
        elif connection_type == ConnectionType.VPN:
            return self.test_vpn_reachability(
                source_vpc, connection_id, protocol, port
            )
        
        elif connection_type == ConnectionType.PRIVATELINK:
            return self.test_privatelink_reachability(
                source_vpc, connection_id, protocol, port
            )
        
        else:
            return TestCase(
                name=f"Unknown-{connection_type.value}",
                result=TestResult.SKIP,
                message=f"Unknown connection type: {connection_type}",
                duration_ms=0
            )
    
    # =========================================================================
    # Helper Methods
    # =========================================================================
    
    def _find_tgw_attachment_arn(self, vpc_id: str, tgw_id: str) -> Optional[str]:
        """Find TGW attachment ARN"""
        
        attachments = self.ec2.describe_transit_gateway_vpc_attachments(
            Filters=[
                {'Name': 'vpc-id', 'Values': [vpc_id]},
                {'Name': 'transit-gateway-id', 'Values': [tgw_id]},
                {'Name': 'state', 'Values': ['available']}
            ]
        )
        
        if not attachments['TransitGatewayVpcAttachments']:
            return None
        
        att = attachments['TransitGatewayVpcAttachments'][0]
        return f"arn:aws:ec2:{self.region}:{att['TransitGatewayOwnerId']}:transit-gateway-attachment/{att['TransitGatewayAttachmentId']}"
    
    def _find_suitable_eni(self, vpc_id: str) -> Optional[str]:
        """Find a suitable ENI for testing (Lambda, NAT GW, etc.)"""
        
        enis = self.ec2.describe_network_interfaces(
            Filters=[
                {'Name': 'vpc-id', 'Values': [vpc_id]},
                {'Name': 'status', 'Values': ['in-use']}
            ]
        )
        
        # Prefer Lambda ENIs (safe to use for testing)
        for eni in enis['NetworkInterfaces']:
            description = eni.get('Description', '').lower()
            if 'lambda' in description or 'AWS Lambda' in description:
                eni_id = eni['NetworkInterfaceId']
                return f"arn:aws:ec2:{self.region}:{eni['OwnerId']}:network-interface/{eni_id}"
        
        # Fallback to any available ENI
        if enis['NetworkInterfaces']:
            eni = enis['NetworkInterfaces'][0]
            eni_id = eni['NetworkInterfaceId']
            return f"arn:aws:ec2:{self.region}:{eni['OwnerId']}:network-interface/{eni_id}"
        
        return None
    
    def _create_reachability_analysis(self,
                                     source_arn: str,
                                     dest_arn: str,
                                     protocol: str,
                                     port: Optional[int]) -> str:
        """Create Network Insights analysis"""
        
        params = {
            'Source': source_arn,
            'Destination': dest_arn,
            'Protocol': protocol
        }
        
        if port and protocol in ['tcp', 'udp']:
            params['DestinationPort'] = port
        
        path = self.ec2.create_network_insights_path(**params)
        path_id = path['NetworkInsightsPath']['NetworkInsightsPathId']
        
        analysis = self.ec2.start_network_insights_analysis(
            NetworkInsightsPathId=path_id
        )
        
        return analysis['NetworkInsightsAnalysis']['NetworkInsightsAnalysisId']
    
    def _wait_for_analysis(self, analysis_id: str, timeout: int = 300) -> Dict:
        """Wait for analysis to complete"""
        
        start = time.time()
        while time.time() - start < timeout:
            response = self.ec2.describe_network_insights_analyses(
                NetworkInsightsAnalysisIds=[analysis_id]
            )
            
            analysis = response['NetworkInsightsAnalyses'][0]
            status = analysis['Status']
            
            if status == 'succeeded':
                return analysis
            elif status == 'failed':
                raise Exception(f"Analysis failed: {analysis.get('StatusMessage')}")
            
            time.sleep(5)
        
        raise TimeoutError("Analysis timeout")


# =============================================================================
# Example Usage
# =============================================================================

if __name__ == "__main__":
    from unified_aft_test_framework import AuthConfig, ExecutionMode
    
    auth = AuthConfig(
        mode=ExecutionMode.LOCAL,
        profile_name='aft-admin'
    )
    
    tester = MultiConnectionReachabilityTester(auth)
    
    # Test TGW connectivity
    result = tester.test_connectivity(
        connection_type=ConnectionType.TRANSIT_GATEWAY,
        source_vpc="vpc-prod",
        dest_vpc="vpc-qa",
        connection_id="tgw-xyz789",
        protocol="tcp",
        port=443
    )
    print(f"TGW Test: {result.result.value} - {result.message}")
    
    # Test VPC Peering
    result = tester.test_connectivity(
        connection_type=ConnectionType.VPC_PEERING,
        source_vpc="vpc-prod",
        dest_vpc="vpc-backup",
        connection_id="pcx-abc123",
        protocol="tcp",
        port=3306  # Database backup
    )
    print(f"Peering Test: {result.result.value} - {result.message}")
    
    # Test VPN
    result = tester.test_connectivity(
        connection_type=ConnectionType.VPN,
        source_vpc="vpc-prod",
        dest_vpc="on-premises",
        connection_id="vpn-def456"
    )
    print(f"VPN Test: {result.result.value} - {result.message}")
