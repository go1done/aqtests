import boto3

def discover_network_intent(account_ids, region='us-east-1'):
    """
    Scans accounts to find where one VPC has a route pointing to 
    a CIDR owned by another VPC.
    """
    inventory = {} # account_id -> { vpc_id -> { 'cidr': str, 'subnets': [] } }
    inferred_paths = []

    # Step 1: Build a global map of VPCs and their CIDRs
    for acc_id in account_ids:
        session = assume_aft_role(acc_id) # Using your existing assume logic
        ec2 = session.client('ec2', region_name=region)
        
        vpcs = ec2.describe_vpcs()['Vpcs']
        for vpc in vpcs:
            v_id = vpc['VpcId']
            inventory.setdefault(acc_id, {})[v_id] = {
                'cidr': vpc['CidrBlock'],
                'subnets': [s['SubnetId'] for s in ec2.describe_subnets(
                    Filters=[{'Name': 'vpc-id', 'Values': [v_id]}]
                )['Subnets']]
            }

        # Step 2: Scan Route Tables for 'Intent'
        rts = ec2.describe_route_tables()['RouteTables']
        for rt in rts:
            for route in rt.get('Routes', []):
                # Ignore local and default internet routes
                if route.get('GatewayId') == 'local' or route.get('DestinationCidrBlock') == '0.0.0.0/0':
                    continue
                
                # Check for TGW or Peering targets
                target = route.get('TransitGatewayId') or route.get('VpcPeeringConnectionId')
                if target:
                    dest_cidr = route.get('DestinationCidrBlock')
                    
                    # Step 3: Find which VPC owns this destination CIDR
                    for peer_acc, peer_vpcs in inventory.items():
                        for peer_vpc_id, peer_meta in peer_vpcs.items():
                            if dest_cidr == peer_meta['cidr']:
                                inferred_paths.append({
                                    'source': {'account': acc_id, 'vpc': rt['VpcId'], 'subnet': rt['Associations'][0].get('SubnetId')},
                                    'dest': {'account': peer_acc, 'vpc': peer_vpc_id, 'subnet': peer_meta['subnets'][0]},
                                    'via': target
                                })
    return inferred_paths
