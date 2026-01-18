"""
Enhanced Connectivity Discovery
Automatically discovers VPC-to-VPC connectivity patterns from:
1. Transit Gateway route tables
2. VPC Flow Logs (actual traffic patterns)
3. Network topology analysis

NO manual connectivity configuration needed!
"""

import boto3
from typing import Dict, List, Set, Tuple, Optional
from dataclasses import dataclass, asdict
from collections import defaultdict
from datetime import datetime, timedelta
import ipaddress

class ConnectionType(Enum):
    TRANSIT_GATEWAY = "tgw"
    VPC_PEERING = "pcx"
    VPN = "vpn"
    DIRECT_CONNECT = "dx"
    PRIVATELINK = "vpce"

@dataclass
class VPCConnectivityPattern:
    """Discovered connectivity between VPCs"""
    source_vpc_id: str
    source_account_id: str
    source_account_name: str
    dest_vpc_id: str
    dest_account_id: str
    dest_account_name: str
    connection_type: ConnectionType
    connection_id: str  # tgw-xxx, pcx-xxx, vpn-xxx, etc.
    expected: bool  # Should this path be reachable?
    traffic_observed: bool  # Have we seen actual traffic?
    protocols_observed: Set[str]
    ports_observed: Set[int]
    first_seen: str
    last_seen: str
    packet_count: int = 0
    use_case: str = "general"  # e.g., "database-backup", "general", "monitoring"

@dataclass
class TGWTopology:
    """Transit Gateway topology"""
    tgw_id: str
    tgw_name: str
    owner_account: str
    route_tables: List[Dict]
    attachments: List[Dict]
    vpc_connectivity_matrix: Dict[str, List[str]]  # vpc_id -> [reachable_vpc_ids]

class ConnectivityDiscovery:
    """
    Discovers VPC-to-VPC connectivity patterns
    Uses multiple sources to build comprehensive connectivity map
    """
    
    def __init__(self, auth_config, hub_account_id: str):
        self.auth = auth_config
        self.hub_account_id = hub_account_id
        self.hub_session = auth_config.get_hub_session()
    
    # =========================================================================
    # OPTION 1A: Discover VPC Peering Connections
    # =========================================================================
    
    def discover_vpc_peering_connections(self, accounts: List[Dict]) -> List[Dict]:
        """
        Discover VPC peering connections across accounts
        Returns list of peering connections with status
        """
        
        print("Discovering VPC Peering connections...")
        
        peering_connections = []
        processed_pcx = set()  # Avoid duplicates
        
        for account in accounts:
            try:
                session = self.auth.assume_role_session(account['account_id'])
                ec2 = session.client('ec2')
                
                # Get all peering connections for this account
                response = ec2.describe_vpc_peering_connections(
                    Filters=[
                        {'Name': 'status-code', 'Values': ['active', 'pending-acceptance']}
                    ]
                )
                
                for pcx in response['VpcPeeringConnections']:
                    pcx_id = pcx['VpcPeeringConnectionId']
                    
                    # Skip if already processed (peering shows up in both accounts)
                    if pcx_id in processed_pcx:
                        continue
                    processed_pcx.add(pcx_id)
                    
                    requester = pcx['RequesterVpcInfo']
                    accepter = pcx['AccepterVpcInfo']
                    
                    peering_connections.append({
                        'peering_id': pcx_id,
                        'status': pcx['Status']['Code'],
                        'requester_vpc': requester['VpcId'],
                        'requester_account': requester['OwnerId'],
                        'requester_cidr': requester.get('CidrBlock'),
                        'accepter_vpc': accepter['VpcId'],
                        'accepter_account': accepter['OwnerId'],
                        'accepter_cidr': accepter.get('CidrBlock'),
                        'tags': {tag['Key']: tag['Value'] for tag in pcx.get('Tags', [])}
                    })
                
            except Exception as e:
                print(f"  ✗ Error discovering peering in {account['account_name']}: {str(e)}")
        
        print(f"  ✓ Found {len(peering_connections)} VPC peering connections")
        
        return peering_connections
    
    # =========================================================================
    # OPTION 1B: Discover VPN Connections
    # =========================================================================
    
    def discover_vpn_connections(self, accounts: List[Dict]) -> List[Dict]:
        """Discover VPN connections (site-to-site, client VPN)"""
        
        print("Discovering VPN connections...")
        
        vpn_connections = []
        
        for account in accounts:
            try:
                session = self.auth.assume_role_session(account['account_id'])
                ec2 = session.client('ec2')
                
                # Site-to-Site VPN
                response = ec2.describe_vpn_connections(
                    Filters=[{'Name': 'state', 'Values': ['available']}]
                )
                
                for vpn in response['VpnConnections']:
                    vpn_connections.append({
                        'vpn_id': vpn['VpnConnectionId'],
                        'type': 'site-to-site',
                        'vpc_id': vpn.get('VpcId'),
                        'customer_gateway_id': vpn['CustomerGatewayId'],
                        'state': vpn['State'],
                        'account_id': account['account_id'],
                        'account_name': account['account_name']
                    })
                
            except Exception as e:
                print(f"  ✗ Error discovering VPN in {account['account_name']}: {str(e)}")
        
        print(f"  ✓ Found {len(vpn_connections)} VPN connections")
        
        return vpn_connections
    
    # =========================================================================
    # OPTION 1C: Discover PrivateLink (VPC Endpoints)
    # =========================================================================
    
    def discover_privatelink_connections(self, accounts: List[Dict]) -> List[Dict]:
        """Discover VPC Endpoint Services and Endpoints"""
        
        print("Discovering PrivateLink connections...")
        
        privatelink_connections = []
        
        for account in accounts:
            try:
                session = self.auth.assume_role_session(account['account_id'])
                ec2 = session.client('ec2')
                
                # VPC Endpoints (consumer side)
                endpoints = ec2.describe_vpc_endpoints(
                    Filters=[{'Name': 'vpc-endpoint-type', 'Values': ['Interface']}]
                )
                
                for endpoint in endpoints['VpcEndpoints']:
                    privatelink_connections.append({
                        'endpoint_id': endpoint['VpcEndpointId'],
                        'type': 'vpc-endpoint',
                        'vpc_id': endpoint['VpcId'],
                        'service_name': endpoint['ServiceName'],
                        'state': endpoint['State'],
                        'account_id': account['account_id'],
                        'account_name': account['account_name']
                    })
                
                # VPC Endpoint Services (provider side)
                services = ec2.describe_vpc_endpoint_service_configurations()
                
                for service in services.get('ServiceConfigurations', []):
                    privatelink_connections.append({
                        'service_id': service['ServiceId'],
                        'type': 'endpoint-service',
                        'service_name': service['ServiceName'],
                        'state': service['ServiceState'],
                        'account_id': account['account_id'],
                        'account_name': account['account_name']
                    })
                
            except Exception as e:
                print(f"  ✗ Error discovering PrivateLink in {account['account_name']}: {str(e)}")
        
        print(f"  ✓ Found {len(privatelink_connections)} PrivateLink connections")
        
        return privatelink_connections
    
    # =========================================================================
    # OPTION 1: Discover from Transit Gateway Route Tables (MOST RELIABLE)
    # =========================================================================
    
    def discover_tgw_topology(self, tgw_id: str) -> TGWTopology:
        """
        Discover VPC connectivity from Transit Gateway route tables
        This tells us which VPCs SHOULD be able to reach each other
        """
        
        ec2 = self.hub_session.client('ec2')
        
        print(f"Discovering TGW topology for {tgw_id}...")
        
        # Get TGW details
        tgws = ec2.describe_transit_gateways(TransitGatewayIds=[tgw_id])
        tgw = tgws['TransitGateways'][0]
        tgw_name = next(
            (tag['Value'] for tag in tgw.get('Tags', []) if tag['Key'] == 'Name'),
            tgw_id
        )
        
        # Get all VPC attachments
        attachments = ec2.describe_transit_gateway_vpc_attachments(
            Filters=[
                {'Name': 'transit-gateway-id', 'Values': [tgw_id]},
                {'Name': 'state', 'Values': ['available']}
            ]
        )
        
        attachment_details = []
        vpc_to_attachment = {}
        
        for att in attachments['TransitGatewayVpcAttachments']:
            vpc_id = att['VpcId']
            att_id = att['TransitGatewayAttachmentId']
            
            attachment_details.append({
                'attachment_id': att_id,
                'vpc_id': vpc_id,
                'vpc_owner_id': att['VpcOwnerId'],
                'subnet_ids': att.get('SubnetIds', [])
            })
            
            vpc_to_attachment[vpc_id] = att_id
        
        # Get TGW route tables
        route_tables = ec2.describe_transit_gateway_route_tables(
            Filters=[{'Name': 'transit-gateway-id', 'Values': [tgw_id]}]
        )
        
        route_table_details = []
        vpc_connectivity = defaultdict(set)
        
        for rt in route_tables['TransitGatewayRouteTables']:
            rt_id = rt['TransitGatewayRouteTableId']
            
            # Get associations (which VPCs use this route table)
            associations = ec2.get_transit_gateway_route_table_associations(
                TransitGatewayRouteTableId=rt_id
            )
            
            # Get routes (where traffic can go)
            routes = ec2.search_transit_gateway_routes(
                TransitGatewayRouteTableId=rt_id,
                Filters=[{'Name': 'state', 'Values': ['active']}]
            )
            
            # Build connectivity matrix
            associated_vpcs = []
            for assoc in associations.get('Associations', []):
                if assoc.get('ResourceType') == 'vpc':
                    resource_id = assoc.get('ResourceId')
                    associated_vpcs.append(resource_id)
            
            # For each route, determine which VPC it points to
            destination_vpcs = set()
            for route in routes.get('Routes', []):
                att_id = route.get('TransitGatewayAttachments', [{}])[0].get('TransitGatewayAttachmentId')
                if att_id:
                    # Find which VPC this attachment belongs to
                    for vpc_id, vpc_att_id in vpc_to_attachment.items():
                        if vpc_att_id == att_id:
                            destination_vpcs.add(vpc_id)
            
            # Each associated VPC can reach destination VPCs
            for source_vpc in associated_vpcs:
                vpc_connectivity[source_vpc].update(destination_vpcs)
            
            route_table_details.append({
                'route_table_id': rt_id,
                'associated_vpcs': associated_vpcs,
                'destination_vpcs': list(destination_vpcs),
                'route_count': len(routes.get('Routes', []))
            })
        
        # Convert connectivity sets to lists
        connectivity_matrix = {
            vpc: list(dests) for vpc, dests in vpc_connectivity.items()
        }
        
        return TGWTopology(
            tgw_id=tgw_id,
            tgw_name=tgw_name,
            owner_account=tgw['OwnerId'],
            route_tables=route_table_details,
            attachments=attachment_details,
            vpc_connectivity_matrix=connectivity_matrix
        )
    
    # =========================================================================
    # OPTION 2: Discover from VPC Flow Logs (ACTUAL TRAFFIC)
    # =========================================================================
    
    def discover_from_flow_logs(self, 
                               vpc_id: str,
                               account_id: str,
                               lookback_hours: int = 24) -> List[Dict]:
        """
        Discover actual traffic patterns from VPC Flow Logs
        Shows what connectivity is ACTUALLY being used
        """
        
        session = self.auth.assume_role_session(account_id)
        logs = session.client('logs')
        ec2 = session.client('ec2')
        
        # Find flow log group
        log_group_name = f"/aws/vpc/flowlogs/{vpc_id}"
        
        # Query for accepted connections to other private IPs
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=lookback_hours)
        
        query = """
        fields @timestamp, srcAddr, dstAddr, srcPort, dstPort, protocol, action, bytes, packets
        | filter action = "ACCEPT"
        | filter (dstAddr like /^10\\./ or dstAddr like /^172\\.1[6-9]\\./ or dstAddr like /^172\\.2[0-9]\\./ or dstAddr like /^172\\.3[0-1]\\./ or dstAddr like /^192\\.168\\./)
        | stats count(*) as packet_count, sum(bytes) as total_bytes by srcAddr, dstAddr, dstPort, protocol
        | sort packet_count desc
        | limit 100
        """
        
        try:
            response = logs.start_query(
                logGroupName=log_group_name,
                startTime=int(start_time.timestamp()),
                endTime=int(end_time.timestamp()),
                queryString=query
            )
            
            query_id = response['queryId']
            
            # Wait for results
            while True:
                result = logs.get_query_results(queryId=query_id)
                status = result['status']
                
                if status == 'Complete':
                    break
                elif status == 'Failed':
                    return []
                
                time.sleep(2)
            
            # Parse results
            traffic_patterns = []
            for row in result.get('results', []):
                row_dict = {item['field']: item['value'] for item in row}
                
                # Determine destination VPC from IP address
                dest_ip = row_dict.get('dstAddr')
                dest_vpc = self._find_vpc_by_ip(dest_ip, ec2)
                
                if dest_vpc and dest_vpc != vpc_id:
                    traffic_patterns.append({
                        'source_vpc': vpc_id,
                        'dest_vpc': dest_vpc,
                        'dest_ip': dest_ip,
                        'protocol': row_dict.get('protocol'),
                        'port': int(row_dict.get('dstPort', 0)),
                        'packet_count': int(row_dict.get('packet_count', 0)),
                        'bytes': int(row_dict.get('total_bytes', 0))
                    })
            
            return traffic_patterns
            
        except logs.exceptions.ResourceNotFoundException:
            print(f"  ⚠️  Flow logs not enabled for VPC {vpc_id}")
            return []
        except Exception as e:
            print(f"  ✗ Flow log query error: {str(e)}")
            return []
    
    def _find_vpc_by_ip(self, ip_address: str, ec2_client) -> Optional[str]:
        """Find which VPC owns a given IP address"""
        
        try:
            ip = ipaddress.ip_address(ip_address)
            
            # Search all VPCs for matching CIDR
            vpcs = ec2_client.describe_vpcs()
            
            for vpc in vpcs['Vpcs']:
                vpc_cidr = ipaddress.ip_network(vpc['CidrBlock'])
                if ip in vpc_cidr:
                    return vpc['VpcId']
                
                # Check secondary CIDRs
                for assoc in vpc.get('CidrBlockAssociationSet', []):
                    if assoc['CidrBlockState']['State'] == 'associated':
                        cidr = ipaddress.ip_network(assoc['CidrBlock'])
                        if ip in cidr:
                            return vpc['VpcId']
            
            return None
            
        except Exception:
            return None
    
    # =========================================================================
    # OPTION 3: Build Complete Connectivity Map
    # =========================================================================
    
    def build_connectivity_map(self, 
                              accounts: List[Dict],
                              tgw_id: str = None,
                              discover_peering: bool = True,
                              discover_vpn: bool = True,
                              discover_privatelink: bool = True,
                              use_flow_logs: bool = True) -> List[VPCConnectivityPattern]:
        """
        Build complete VPC-to-VPC connectivity map
        Discovers ALL connection types: TGW, Peering, VPN, PrivateLink
        
        Returns list of all VPC-to-VPC connections that should be tested
        """
        
        print("\n" + "="*80)
        print("DISCOVERING ALL CONNECTIVITY TYPES")
        print("="*80)
        
        connectivity_patterns = []
        account_map = {acc['account_id']: acc['account_name'] for acc in accounts}
        vpc_to_account = {acc['vpc_id']: acc for acc in accounts}
        
        # =====================================================================
        # 1. Transit Gateway Connectivity
        # =====================================================================
        if tgw_id:
            print("\n[1/4] Transit Gateway Connectivity")
            tgw_topology = self.discover_tgw_topology(tgw_id)
            
            print(f"  ✓ Found {len(tgw_topology.attachments)} VPC attachments")
            print(f"  ✓ Found {len(tgw_topology.route_tables)} route tables")
            
            for source_vpc, dest_vpcs in tgw_topology.vpc_connectivity_matrix.items():
                source_acc = vpc_to_account.get(source_vpc, {})
                
                for dest_vpc in dest_vpcs:
                    if source_vpc == dest_vpc:
                        continue
                    
                    dest_acc = vpc_to_account.get(dest_vpc, {})
                    
                    connectivity_patterns.append(VPCConnectivityPattern(
                        source_vpc_id=source_vpc,
                        source_account_id=source_acc.get('account_id', 'unknown'),
                        source_account_name=source_acc.get('account_name', 'unknown'),
                        dest_vpc_id=dest_vpc,
                        dest_account_id=dest_acc.get('account_id', 'unknown'),
                        dest_account_name=dest_acc.get('account_name', 'unknown'),
                        connection_type=ConnectionType.TRANSIT_GATEWAY,
                        connection_id=tgw_id,
                        expected=True,
                        traffic_observed=False,
                        protocols_observed=set(),
                        ports_observed=set(),
                        first_seen=datetime.utcnow().isoformat(),
                        last_seen=datetime.utcnow().isoformat(),
                        use_case="general"
                    ))
            
            print(f"  ✓ Discovered {len(connectivity_patterns)} TGW connectivity paths")
        
        # =====================================================================
        # 2. VPC Peering Connectivity
        # =====================================================================
        if discover_peering:
            print("\n[2/4] VPC Peering Connectivity")
            peering_conns = self.discover_vpc_peering_connections(accounts)
            
            for pcx in peering_conns:
                requester_acc = next((a for a in accounts if a['vpc_id'] == pcx['requester_vpc']), {})
                accepter_acc = next((a for a in accounts if a['vpc_id'] == pcx['accepter_vpc']), {})
                
                # Check tags for use case
                use_case = pcx['tags'].get('UseCase', pcx['tags'].get('Purpose', 'general'))
                
                # Bi-directional connectivity
                for source, dest in [(pcx['requester_vpc'], pcx['accepter_vpc']),
                                    (pcx['accepter_vpc'], pcx['requester_vpc'])]:
                    
                    source_acc = requester_acc if source == pcx['requester_vpc'] else accepter_acc
                    dest_acc = accepter_acc if dest == pcx['accepter_vpc'] else requester_acc
                    
                    connectivity_patterns.append(VPCConnectivityPattern(
                        source_vpc_id=source,
                        source_account_id=source_acc.get('account_id', 'unknown'),
                        source_account_name=source_acc.get('account_name', 'unknown'),
                        dest_vpc_id=dest,
                        dest_account_id=dest_acc.get('account_id', 'unknown'),
                        dest_account_name=dest_acc.get('account_name', 'unknown'),
                        connection_type=ConnectionType.VPC_PEERING,
                        connection_id=pcx['peering_id'],
                        expected=pcx['status'] == 'active',
                        traffic_observed=False,
                        protocols_observed=set(),
                        ports_observed=set(),
                        first_seen=datetime.utcnow().isoformat(),
                        last_seen=datetime.utcnow().isoformat(),
                        use_case=use_case
                    ))
            
            peering_count = sum(1 for p in connectivity_patterns if p.connection_type == ConnectionType.VPC_PEERING)
            print(f"  ✓ Discovered {peering_count} VPC Peering connectivity paths")
        
        # =====================================================================
        # 3. VPN Connectivity
        # =====================================================================
        if discover_vpn:
            print("\n[3/4] VPN Connectivity")
            vpn_conns = self.discover_vpn_connections(accounts)
            
            for vpn in vpn_conns:
                if vpn.get('vpc_id'):
                    vpc_acc = next((a for a in accounts if a['vpc_id'] == vpn['vpc_id']), {})
                    
                    connectivity_patterns.append(VPCConnectivityPattern(
                        source_vpc_id=vpn['vpc_id'],
                        source_account_id=vpc_acc.get('account_id', 'unknown'),
                        source_account_name=vpc_acc.get('account_name', 'unknown'),
                        dest_vpc_id='on-premises',  # Special marker for on-prem
                        dest_account_id='external',
                        dest_account_name='On-Premises',
                        connection_type=ConnectionType.VPN,
                        connection_id=vpn['vpn_id'],
                        expected=vpn['state'] == 'available',
                        traffic_observed=False,
                        protocols_observed=set(),
                        ports_observed=set(),
                        first_seen=datetime.utcnow().isoformat(),
                        last_seen=datetime.utcnow().isoformat(),
                        use_case="hybrid-connectivity"
                    ))
            
            vpn_count = sum(1 for p in connectivity_patterns if p.connection_type == ConnectionType.VPN)
            print(f"  ✓ Discovered {vpn_count} VPN connectivity paths")
        
        # =====================================================================
        # 4. PrivateLink Connectivity
        # =====================================================================
        if discover_privatelink:
            print("\n[4/4] PrivateLink Connectivity")
            privatelink_conns = self.discover_privatelink_connections(accounts)
            
            # Group endpoints by service
            for pl in privatelink_conns:
                if pl['type'] == 'vpc-endpoint':
                    vpc_acc = next((a for a in accounts if a['vpc_id'] == pl['vpc_id']), {})
                    
                    connectivity_patterns.append(VPCConnectivityPattern(
                        source_vpc_id=pl['vpc_id'],
                        source_account_id=vpc_acc.get('account_id', 'unknown'),
                        source_account_name=vpc_acc.get('account_name', 'unknown'),
                        dest_vpc_id='privatelink-service',
                        dest_account_id='service',
                        dest_account_name=pl['service_name'],
                        connection_type=ConnectionType.PRIVATELINK,
                        connection_id=pl['endpoint_id'],
                        expected=pl['state'] == 'available',
                        traffic_observed=False,
                        protocols_observed=set(),
                        ports_observed=set(),
                        first_seen=datetime.utcnow().isoformat(),
                        last_seen=datetime.utcnow().isoformat(),
                        use_case="service-access"
                    ))
            
            pl_count = sum(1 for p in connectivity_patterns if p.connection_type == ConnectionType.PRIVATELINK)
            print(f"  ✓ Discovered {pl_count} PrivateLink connectivity paths")
        
        print(f"\n{'='*80}")
        print(f"TOTAL CONNECTIVITY PATHS DISCOVERED: {len(connectivity_patterns)}")
        print(f"{'='*80}")
        
        # Print summary by type
        by_type = defaultdict(int)
        for p in connectivity_patterns:
            by_type[p.connection_type.value] += 1
        
        print("\nBy Connection Type:")
        for conn_type, count in sorted(by_type.items()):
            print(f"  {conn_type.upper()}: {count}")
        
        # =====================================================================
        # 5. Enhance with Flow Logs (actual traffic)
        # =====================================================================
        if use_flow_logs:
            print("\nAnalyzing VPC Flow Logs for actual traffic patterns...")
            
            traffic_data = defaultdict(lambda: {
                'protocols': set(),
                'ports': set(),
                'packet_count': 0
            })
            
            for account in accounts:
                vpc_id = account['vpc_id']
                account_id = account['account_id']
                
                print(f"  Checking flow logs for {account['account_name']}...")
                
                traffic = self.discover_from_flow_logs(vpc_id, account_id, lookback_hours=24)
                
                for t in traffic:
                    key = (t['source_vpc'], t['dest_vpc'])
                    traffic_data[key]['protocols'].add(t['protocol'])
                    traffic_data[key]['ports'].add(t['port'])
                    traffic_data[key]['packet_count'] += t['packet_count']
            
            # Update patterns with traffic data
            for pattern in connectivity_patterns:
                key = (pattern.source_vpc_id, pattern.dest_vpc_id)
                if key in traffic_data:
                    pattern.traffic_observed = True
                    pattern.protocols_observed = traffic_data[key]['protocols']
                    pattern.ports_observed = traffic_data[key]['ports']
                    pattern.packet_count = traffic_data[key]['packet_count']
            
            observed_count = sum(1 for p in connectivity_patterns if p.traffic_observed)
            print(f"\n✓ Found actual traffic on {observed_count}/{len(connectivity_patterns)} paths")
        
        return connectivity_patterns
    
    def save_connectivity_map(self, patterns: List[VPCConnectivityPattern], filename: str):
        """Save connectivity map to golden path"""
        
        connectivity_data = {
            'vpc_connectivity': [
                {
                    'source_vpc': p.source_vpc_id,
                    'source_account': p.source_account_name,
                    'dest_vpc': p.dest_vpc_id,
                    'dest_account': p.dest_account_name,
                    'connection_type': p.connection_type.value,
                    'connection_id': p.connection_id,
                    'expected_reachable': p.expected,
                    'traffic_observed': p.traffic_observed,
                    'protocols_observed': list(p.protocols_observed),
                    'ports_observed': sorted(list(p.ports_observed)),
                    'packet_count': p.packet_count,
                    'use_case': p.use_case
                }
                for p in patterns
            ],
            'discovered_at': datetime.utcnow().isoformat(),
            'total_paths': len(patterns),
            'active_paths': sum(1 for p in patterns if p.traffic_observed),
            'by_connection_type': {
                'tgw': sum(1 for p in patterns if p.connection_type == ConnectionType.TRANSIT_GATEWAY),
                'peering': sum(1 for p in patterns if p.connection_type == ConnectionType.VPC_PEERING),
                'vpn': sum(1 for p in patterns if p.connection_type == ConnectionType.VPN),
                'privatelink': sum(1 for p in patterns if p.connection_type == ConnectionType.PRIVATELINK)
            }
        }
        
        import yaml
        with open(filename, 'r') as f:
            golden_path = yaml.safe_load(f)
        
        golden_path['connectivity'] = connectivity_data
        
        with open(filename, 'w') as f:
            yaml.dump(golden_path, f, default_flow_style=False)
        
        print(f"\n✓ Connectivity map saved to {filename}")
        print(f"  - TGW paths: {connectivity_data['by_connection_type']['tgw']}")
        print(f"  - Peering paths: {connectivity_data['by_connection_type']['peering']}")
        print(f"  - VPN paths: {connectivity_data['by_connection_type']['vpn']}")
        print(f"  - PrivateLink paths: {connectivity_data['by_connection_type']['privatelink']}")


# =============================================================================
# INTEGRATION WITH TEST ORCHESTRATOR
# =============================================================================

class EnhancedAFTTestOrchestrator:
    """
    Enhanced orchestrator with automatic connectivity discovery
    NO manual source/dest VPC configuration needed!
    """
    
    def __init__(self, auth_config, golden_path_file: str = None, s3_bucket: str = None):
        self.auth = auth_config
        self.golden_path_file = golden_path_file
        self.s3_bucket = s3_bucket
        self.connectivity_discovery = ConnectivityDiscovery(
            auth_config, 
            hub_account_id=auth_config.get_hub_session().client('sts').get_caller_identity()['Account']
        )
    
    def discover_full_baseline(self, accounts: List[Dict], tgw_id: str) -> Dict:
        """
        Complete discovery:
        1. VPC configurations (security groups, routes, etc.)
        2. VPC-to-VPC connectivity patterns
        """
        
        # Original baseline discovery
        from unified_aft_test_framework import BaselineDiscovery
        baseline_discovery = BaselineDiscovery(self.auth)
        baselines = baseline_discovery.scan_all_accounts(accounts)
        golden_path = baseline_discovery.generate_golden_path(baselines)
        
        # NEW: Connectivity discovery
        connectivity_patterns = self.connectivity_discovery.build_connectivity_map(
            accounts, 
            tgw_id,
            use_flow_logs=True
        )
        
        # Save both to golden path
        import yaml
        golden_path['connectivity'] = {
            'patterns': [asdict(p) for p in connectivity_patterns],
            'tgw_id': tgw_id,
            'total_paths': len(connectivity_patterns)
        }
        
        with open(self.golden_path_file, 'w') as f:
            yaml.dump(golden_path, f, default_flow_style=False)
        
        return golden_path
    
    def generate_reachability_tests(self) -> List[Dict]:
        """
        Generate reachability tests from discovered connectivity
        NO manual configuration of source/dest VPCs!
        """
        
        import yaml
        with open(self.golden_path_file, 'r') as f:
            golden_path = yaml.safe_load(f)
        
        connectivity = golden_path.get('connectivity', {})
        patterns = connectivity.get('patterns', [])
        
        test_cases = []
        
        for pattern in patterns:
            # Only test expected paths
            if not pattern.get('expected_reachable'):
                continue
            
            # Determine what ports to test
            ports_to_test = set()
            
            # If we observed traffic, test those ports
            if pattern.get('traffic_observed'):
                ports_to_test.update(pattern.get('ports_observed', []))
            
            # Always test protocol-level connectivity
            test_cases.append({
                'source_vpc': pattern['source_vpc'],
                'dest_vpc': pattern['dest_vpc'],
                'tgw_id': pattern['via_tgw'],
                'protocol': '-1',
                'port': None,
                'name': f"{pattern['source_account']} → {pattern['dest_account']} (Protocol)"
            })
            
            # Test specific ports if we know about them
            for port in sorted(ports_to_test):
                test_cases.append({
                    'source_vpc': pattern['source_vpc'],
                    'dest_vpc': pattern['dest_vpc'],
                    'tgw_id': pattern['via_tgw'],
                    'protocol': 'tcp',
                    'port': port,
                    'name': f"{pattern['source_account']} → {pattern['dest_account']} (TCP:{port})"
                })
        
        print(f"\n✓ Generated {len(test_cases)} reachability tests from discovered connectivity")
        
        return test_cases


# =============================================================================
# USAGE EXAMPLE
# =============================================================================

if __name__ == "__main__":
    from unified_aft_test_framework import AuthConfig, ExecutionMode
    
    # Setup
    auth = AuthConfig(
        mode=ExecutionMode.LOCAL,
        profile_name='aft-admin',
        region='us-east-1'
    )
    
    accounts = [
        {'account_id': '111111111111', 'account_name': 'prod-app1', 'vpc_id': 'vpc-abc123'},
        {'account_id': '222222222222', 'account_name': 'qa-app1', 'vpc_id': 'vpc-def456'},
        {'account_id': '333333333333', 'account_name': 'dev-app1', 'vpc_id': 'vpc-ghi789'},
    ]
    
    tgw_id = 'tgw-xyz789'
    
    # Discover connectivity
    orchestrator = EnhancedAFTTestOrchestrator(
        auth_config=auth,
        golden_path_file='./golden_path.yaml'
    )
    
    print("="*80)
    print("STEP 1: DISCOVER FULL BASELINE (Config + Connectivity)")
    print("="*80)
    
    golden_path = orchestrator.discover_full_baseline(accounts, tgw_id)
    
    print("\n" + "="*80)
    print("STEP 2: GENERATE AUTO-CONFIGURED TESTS")
    print("="*80)
    
    test_cases = orchestrator.generate_reachability_tests()
    
    print("\nTest Cases Generated:")
    for i, test in enumerate(test_cases[:10], 1):  # Show first 10
        print(f"{i}. {test['name']}")
        print(f"   {test['source_vpc']} → {test['dest_vpc']}")
        print(f"   Protocol: {test['protocol']}, Port: {test.get('port', 'N/A')}")
        print()
