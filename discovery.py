import networkx as nx

def discover_vpcs(session):
    ec2 = session.client("ec2")
    vpcs = []

    resp = ec2.describe_vpcs()
    for vpc in resp["Vpcs"]:
        vpcs.append({
            "vpc_id": vpc["VpcId"],
            "cidr": vpc["CidrBlock"]
        })
    return vpcs


def discover_tgw_attachments(session):
    ec2 = session.client("ec2")
    attachments = []

    resp = ec2.describe_transit_gateway_vpc_attachments()
    for att in resp["TransitGatewayVpcAttachments"]:
        attachments.append({
            "tgw_attachment_id": att["TransitGatewayAttachmentId"],
            "vpc_id": att["VpcId"],
            "account": att["VpcOwnerId"]
        })
    return attachments


def build_graph(vpcs, attachments):
    graph = nx.DiGraph()

    for vpc in vpcs:
        graph.add_node(vpc["cidr"], type="vpc")

    for att in attachments:
        graph.add_edge(att["vpc_id"], "TGW")

    return graph
