import json
import boto3

def get_connections_from_state(state_file):
    with open(state_file, 'r') as f:
        state = json.load(f)

    connections = []
    for resource in state.get('resources', []):
        # Identify VPC Peering
        if resource['type'] == 'aws_vpc_peering_connection':
            for instance in resource['instances']:
                connections.append({
                    'type': 'peering',
                    'source_vpc': instance['attributes']['vpc_id'],
                    'dest_vpc': instance['attributes']['peer_vpc_id'],
                    'id': instance['attributes']['id']
                })
        
        # Identify Transit Gateway Attachments
        elif resource['type'] == 'aws_ec2_transit_gateway_vpc_attachment':
            for instance in resource['instances']:
                connections.append({
                    'type': 'tgw',
                    'tgw_id': instance['attributes']['transit_gateway_id'],
                    'vpc_id': instance['attributes']['vpc_id'],
                    'id': instance['attributes']['id']
                })
    return connections