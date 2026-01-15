"""
AFT Baseline Discovery Tool
Discovers current network configuration across AFT accounts
Establishes golden path baseline that can be manually refined
"""

import boto3
import json
import yaml
from typing import Dict, List, Set, Optional
from dataclasses import dataclass, asdict
from collections import defaultdict
from datetime import datetime

@dataclass
class VPCBaseline:
    vpc_id: str
    cidr_block: str
    cidr_block_associations: List[str]
    dns_support: bool
    dns_hostnames: bool
    subnet_count: int
    subnet_cidrs: List[str]
    availability_zones: List[str]
    
@dataclass
class TransitGatewayBaseline:
    tgw_id: str
    tgw_attachment_id: str
    attachment_state: str
    subnet_ids: List[str]
    route_table_id: Optional[str]
    appliance_mode: bool
    
@dataclass
class RouteTableBaseline:
    route_table_id: str
    main: bool
    routes: List[Dict]
    associated_subnets: List[str]
    
@dataclass
class SecurityGroupBaseline:
    group_id: str
    group_name: str
    ingress_rules: List[Dict]
    egress_rules: List[Dict]
    
@dataclass
class NetworkACLBaseline:
    nacl_id: str
    ingress_rules: List[Dict]
    egress_rules: List[Dict]
    associated_subnets: List[str]

@dataclass
class AccountNetworkBaseline:
    account_id: str
    account_name: str
    region: str
    vpc: VPCBaseline
    transit_gateway: Optional[TransitGatewayBaseline]
    route_tables: List[RouteTableBaseline]
    security_groups: List[SecurityGroupBaseline]
    network_acls: List[NetworkACLBaseline]
    discovered_at: str
    tags: Dict[str, str]

class BaselineDiscovery:
    def __init__(self, hub_account_id: str, region: str = "us-east-1"):
        self.hub_account_id = hub_account_id
        self.region = region
        self.hub_session = boto3.Session(region_name=region)
        
    def assume_aft_role(self, account_id: str, role_name: str = "AWSAFTExecution") -> boto3.Session:
        """Assume AFTExecution role in target account"""
        sts = self.hub_session.client('sts')
        role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
        
        response = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName=f"aft-baseline-discovery-{int(datetime.now().timestamp())}"
        )
        
        return boto3.Session(
            aws_access_key_id=response['Credentials']['AccessKeyId'],
            aws_secret_access_key=response['Credentials']['SecretAccessKey'],
            aws_session_token=response['Credentials']['SessionToken'],
            region_name=self.region
        )
    
    def discover_vpc_baseline(self, ec2_client, vpc_id: str) -> VPCBaseline:
        """Discover VPC configuration"""
        vpcs = ec2_client.describe_vpcs(VpcIds=[vpc_id])
        vpc = vpcs['Vpcs'][0]
        
        subnets = ec2_client.describe_subnets(
            Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}]
        )
        
        return VPCBaseline(
            vpc_id=vpc_id,
            cidr_block=vpc['CidrBlock'],
            cidr_block_associations=[
                assoc['CidrBlock'] 
                for assoc in vpc.get('CidrBlockAssociationSet', [])
                if assoc['CidrBlockState']['State'] == 'associated'
            ],
            dns_support=vpc.get('EnableDnsSupport', False),
            dns_hostnames=vpc.get('EnableDnsHostnames', False),
            subnet_count=len(subnets['Subnets']),
            subnet_cidrs=[s['CidrBlock'] for s in subnets['Subnets']],
            availability_zones=list(set(s['AvailabilityZone'] for s in subnets['Subnets']))
        )
    
    def discover_transit_gateway(self, ec2_client, vpc_id: str) -> Optional[TransitGatewayBaseline]:
        """Discover Transit Gateway attachment"""
        attachments = ec2_client.describe_transit_gateway_vpc_attachments(
            Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}]
        )
        
        if not attachments['TransitGatewayVpcAttachments']:
            return None
        
        att = attachments['TransitGatewayVpcAttachments'][0]
        
        # Try to get route table association
        route_table_id = None
        try:
            associations = ec2_client.describe_transit_gateway_route_tables(
                Filters=[
                    {'Name': 'transit-gateway-id', 'Values': [att['TransitGatewayId']]}
                ]
            )
            if associations['TransitGatewayRouteTables']:
                route_table_id = associations['TransitGatewayRouteTables'][0]['TransitGatewayRouteTableId']
        except:
            pass
        
        return TransitGatewayBaseline(
            tgw_id=att['TransitGatewayId'],
            tgw_attachment_id=att['TransitGatewayAttachmentId'],
            attachment_state=att['State'],
            subnet_ids=att.get('SubnetIds', []),
            route_table_id=route_table_id,
            appliance_mode=att.get('Options', {}).get('ApplianceModeSupport') == 'enable'
        )
    
    def discover_route_tables(self, ec2_client, vpc_id: str) -> List[RouteTableBaseline]:
        """Discover route table configurations"""
        route_tables = ec2_client.describe_route_tables(
            Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}]
        )
        
        baselines = []
        for rt in route_tables['RouteTables']:
            routes = []
            for route in rt['Routes']:
                route_info = {
                    'destination': route.get('DestinationCidrBlock', route.get('DestinationPrefixListId')),
                    'target': (
                        route.get('GatewayId') or 
                        route.get('TransitGatewayId') or 
                        route.get('NatGatewayId') or 
                        route.get('NetworkInterfaceId') or 
                        'local'
                    ),
                    'state': route.get('State', 'active')
                }
                routes.append(route_info)
            
            associated_subnets = [
                assoc['SubnetId'] 
                for assoc in rt.get('Associations', [])
                if 'SubnetId' in assoc
            ]
            
            baselines.append(RouteTableBaseline(
                route_table_id=rt['RouteTableId'],
                main=any(assoc.get('Main', False) for assoc in rt.get('Associations', [])),
                routes=routes,
                associated_subnets=associated_subnets
            ))
        
        return baselines
    
    def discover_security_groups(self, ec2_client, vpc_id: str) -> List[SecurityGroupBaseline]:
        """Discover security group configurations"""
        security_groups = ec2_client.describe_security_groups(
            Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}]
        )
        
        baselines = []
        for sg in security_groups['SecurityGroups']:
            # Skip default SG for cleaner baseline
            if sg['GroupName'] == 'default':
                continue
            
            ingress_rules = []
            for rule in sg.get('IpPermissions', []):
                ingress_rules.append({
                    'protocol': rule.get('IpProtocol'),
                    'from_port': rule.get('FromPort'),
                    'to_port': rule.get('ToPort'),
                    'cidr_blocks': [ip['CidrIp'] for ip in rule.get('IpRanges', [])],
                    'source_sgs': [sg['GroupId'] for sg in rule.get('UserIdGroupPairs', [])]
                })
            
            egress_rules = []
            for rule in sg.get('IpPermissionsEgress', []):
                egress_rules.append({
                    'protocol': rule.get('IpProtocol'),
                    'from_port': rule.get('FromPort'),
                    'to_port': rule.get('ToPort'),
                    'cidr_blocks': [ip['CidrIp'] for ip in rule.get('IpRanges', [])],
                    'dest_sgs': [sg['GroupId'] for sg in rule.get('UserIdGroupPairs', [])]
                })
            
            baselines.append(SecurityGroupBaseline(
                group_id=sg['GroupId'],
                group_name=sg['GroupName'],
                ingress_rules=ingress_rules,
                egress_rules=egress_rules
            ))
        
        return baselines
    
    def discover_network_acls(self, ec2_client, vpc_id: str) -> List[NetworkACLBaseline]:
        """Discover Network ACL configurations"""
        nacls = ec2_client.describe_network_acls(
            Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}]
        )
        
        baselines = []
        for nacl in nacls['NetworkAcls']:
            ingress_rules = [
                {
                    'rule_number': entry['RuleNumber'],
                    'protocol': entry['Protocol'],
                    'action': entry['RuleAction'],
                    'cidr_block': entry.get('CidrBlock'),
                    'port_range': entry.get('PortRange')
                }
                for entry in nacl.get('Entries', [])
                if not entry['Egress']
            ]
            
            egress_rules = [
                {
                    'rule_number': entry['RuleNumber'],
                    'protocol': entry['Protocol'],
                    'action': entry['RuleAction'],
                    'cidr_block': entry.get('CidrBlock'),
                    'port_range': entry.get('PortRange')
                }
                for entry in nacl.get('Entries', [])
                if entry['Egress']
            ]
            
            associated_subnets = [
                assoc['SubnetId']
                for assoc in nacl.get('Associations', [])
            ]
            
            # Skip default NACLs unless they have custom rules
            if nacl.get('IsDefault') and len(ingress_rules) <= 2:
                continue
            
            baselines.append(NetworkACLBaseline(
                nacl_id=nacl['NetworkAclId'],
                ingress_rules=ingress_rules,
                egress_rules=egress_rules,
                associated_subnets=associated_subnets
            ))
        
        return baselines
    
    def discover_account_baseline(self, account_id: str, account_name: str) -> Optional[AccountNetworkBaseline]:
        """Discover complete network baseline for an account"""
        try:
            print(f"Discovering baseline for {account_name} ({account_id})...")
            
            session = self.assume_aft_role(account_id)
            ec2 = session.client('ec2')
            
            # Find VPCs (excluding default)
            vpcs = ec2.describe_vpcs(
                Filters=[{'Name': 'is-default', 'Values': ['false']}]
            )
            
            if not vpcs['Vpcs']:
                print(f"  No non-default VPCs found in {account_name}")
                return None
            
            # Use first non-default VPC
            vpc_id = vpcs['Vpcs'][0]['VpcId']
            vpc_tags = {tag['Key']: tag['Value'] for tag in vpcs['Vpcs'][0].get('Tags', [])}
            
            baseline = AccountNetworkBaseline(
                account_id=account_id,
                account_name=account_name,
                region=self.region,
                vpc=self.discover_vpc_baseline(ec2, vpc_id),
                transit_gateway=self.discover_transit_gateway(ec2, vpc_id),
                route_tables=self.discover_route_tables(ec2, vpc_id),
                security_groups=self.discover_security_groups(ec2, vpc_id),
                network_acls=self.discover_network_acls(ec2, vpc_id),
                discovered_at=datetime.utcnow().isoformat(),
                tags=vpc_tags
            )
            
            print(f"  ✓ Discovered VPC {vpc_id}")
            print(f"  ✓ Found {len(baseline.route_tables)} route tables")
            print(f"  ✓ Found {len(baseline.security_groups)} security groups")
            
            return baseline
            
        except Exception as e:
            print(f"  ✗ Error discovering {account_name}: {str(e)}")
            return None
    
    def generate_golden_path(self, baselines: List[AccountNetworkBaseline]) -> Dict:
        """Analyze baselines and generate golden path configuration"""
        
        print(f"\nAnalyzing {len(baselines)} accounts to generate golden path...")
        
        # Aggregate common patterns
        common_routes = defaultdict(int)
        common_tgw_config = []
        common_sg_patterns = defaultdict(int)
        
        for baseline in baselines:
            # Count route patterns
            for rt in baseline.route_tables:
                for route in rt.routes:
                    if route['destination'] != 'local':
                        route_key = f"{route['destination']} -> {route['target'].split('/')[0]}"
                        common_routes[route_key] += 1
            
            # TGW patterns
            if baseline.transit_gateway:
                common_tgw_config.append({
                    'appliance_mode': baseline.transit_gateway.appliance_mode,
                    'state': baseline.transit_gateway.attachment_state
                })
            
            # Security group patterns
            for sg in baseline.security_groups:
                for rule in sg.ingress_rules:
                    rule_key = f"{rule['protocol']}:{rule.get('from_port', 'all')}-{rule.get('to_port', 'all')}"
                    common_sg_patterns[rule_key] += 1
        
        # Determine golden path (patterns appearing in >50% of accounts)
        threshold = len(baselines) * 0.5
        
        golden_routes = [
            route for route, count in common_routes.items()
            if count >= threshold
        ]
        
        golden_path = {
            'version': '1.0',
            'generated_at': datetime.utcnow().isoformat(),
            'based_on_accounts': len(baselines),
            'threshold_percentage': 50,
            
            'expected_configuration': {
                'vpc': {
                    'dns_support': all(b.vpc.dns_support for b in baselines),
                    'dns_hostnames': all(b.vpc.dns_hostnames for b in baselines),
                    'min_subnets': min(b.vpc.subnet_count for b in baselines),
                    'min_availability_zones': 2
                },
                
                'transit_gateway': {
                    'required': any(b.transit_gateway for b in baselines),
                    'expected_state': 'available',
                    'appliance_mode': any(
                        b.transit_gateway and b.transit_gateway.appliance_mode 
                        for b in baselines
                    )
                },
                
                'routes': {
                    'expected_destinations': golden_routes,
                    'description': 'Routes appearing in >50% of accounts'
                },
                
                'security': {
                    'common_ingress_patterns': [
                        pattern for pattern, count in common_sg_patterns.items()
                        if count >= threshold
                    ]
                }
            },
            
            'account_specific_overrides': {
                baseline.account_name: {
                    'vpc_id': baseline.vpc.vpc_id,
                    'cidr_block': baseline.vpc.cidr_block,
                    'custom_routes': [
                        f"{route['destination']} -> {route['target']}"
                        for rt in baseline.route_tables
                        for route in rt.routes
                        if route['destination'] != 'local'
                    ][:5]  # First 5 custom routes
                }
                for baseline in baselines
            }
        }
        
        return golden_path
    
    def export_baseline(self, baselines: List[AccountNetworkBaseline], 
                       golden_path: Dict, output_dir: str = "."):
        """Export baselines and golden path to files"""
        
        # Export individual baselines
        for baseline in baselines:
            filename = f"{output_dir}/baseline_{baseline.account_name}_{baseline.account_id}.json"
            with open(filename, 'w') as f:
                json.dump(asdict(baseline), f, indent=2, default=str)
            print(f"Exported: {filename}")
        
        # Export golden path as YAML (easier to edit manually)
        golden_path_file = f"{output_dir}/golden_path.yaml"
        with open(golden_path_file, 'w') as f:
            yaml.dump(golden_path, f, default_flow_style=False, sort_keys=False)
        print(f"Exported: {golden_path_file}")
        
        # Export golden path as JSON too
        golden_path_json = f"{output_dir}/golden_path.json"
        with open(golden_path_json, 'w') as f:
            json.dump(golden_path, f, indent=2)
        print(f"Exported: {golden_path_json}")
        
        # Generate test configuration for orchestrator
        test_config = {
            'accounts': [
                {
                    'account_id': b.account_id,
                    'account_name': b.account_name,
                    'vpc_id': b.vpc.vpc_id,
                    'test_endpoint_ip': 'TO_BE_CONFIGURED',  # User fills this in
                    'expected_routes': [
                        route.split(' -> ')[0]
                        for route in golden_path['expected_configuration']['routes']['expected_destinations']
                    ]
                }
                for b in baselines
            ]
        }
        
        test_config_file = f"{output_dir}/test_config.yaml"
        with open(test_config_file, 'w') as f:
            yaml.dump(test_config, f, default_flow_style=False)
        print(f"Exported: {test_config_file}")
        
        print(f"\n✓ Baseline discovery complete!")
        print(f"✓ Review and edit {golden_path_file} to refine your golden path")
        print(f"✓ Update {test_config_file} with test endpoint IPs")


# Example usage
if __name__ == "__main__":
    # Initialize discovery
    discovery = BaselineDiscovery(
        hub_account_id="123456789012",
        region="us-east-1"
    )
    
    # Define accounts to scan (from AFT or manually)
    accounts_to_scan = [
        ("111111111111", "prod-app1"),
        ("222222222222", "qa-app1"),
        ("333333333333", "dev-app1"),
    ]
    
    # Discover baselines
    baselines = []
    for account_id, account_name in accounts_to_scan:
        baseline = discovery.discover_account_baseline(account_id, account_name)
        if baseline:
            baselines.append(baseline)
    
    # Generate golden path
    golden_path = discovery.generate_golden_path(baselines)
    
    # Export everything
    discovery.export_baseline(baselines, golden_path, output_dir="./baselines")
    
    print("\n" + "="*60)
    print("Next Steps:")
    print("="*60)
    print("1. Review ./baselines/golden_path.yaml")
    print("2. Manually add/remove expected configurations")
    print("3. Update ./baselines/test_config.yaml with test IPs")
    print("4. Run test orchestrator with the config")
    print("="*60)
