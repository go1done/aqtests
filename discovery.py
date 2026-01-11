import networkx as nx


# -----------------------------
# VPC DISCOVERY
# -----------------------------

def discover_vpcs(session):
    ec2 = session.client("ec2")
    vpcs = []

    for vpc in ec2.describe_vpcs()["Vpcs"]:
        vpcs.append({
            "vpc_id": vpc["VpcId"],
            "cidr": vpc["CidrBlock"],
            "owner": vpc["OwnerId"]
        })
    return vpcs


# -----------------------------
# VPC ROUTE TABLE SCANNING
# -----------------------------

def discover_vpc_routes(session):
    """
    Discovers routes from VPC subnet route tables that explicitly
    send traffic to a Transit Gateway.
    """
    ec2 = session.client("ec2")
    routes = []

    resp = ec2.describe_route_tables()

    for rtb in resp["RouteTables"]:
        vpc_id = rtb.get("VpcId")
        for route in rtb.get("Routes", []):
            if route.get("TransitGatewayId"):
                if route.get("DestinationCidrBlock"):
                    routes.append({
                        "vpc_id": vpc_id,
                        "destination": route["DestinationCidrBlock"],
                        "tgw_id": route["TransitGatewayId"]
                    })
    return routes


# -----------------------------
# TGW ROUTE TABLE SCANNING
# -----------------------------

def discover_tgw_routes(session):
    """
    Discovers TGW route tables and how CIDRs map to attachments.
    """
    ec2 = session.client("ec2")
    tgw_routes = []

    rtbs = ec2.describe_transit_gateway_route_tables()[
        "TransitGatewayRouteTables"
    ]

    for rtb in rtbs:
        rtb_id = rtb["TransitGatewayRouteTableId"]

        routes = ec2.search_transit_gateway_routes(
            TransitGatewayRouteTableId=rtb_id,
            Filters=[{"Name": "state", "Values": ["active"]}]
        )["Routes"]

        for route in routes:
            if "DestinationCidrBlock" in route:
                for att in route.get("TransitGatewayAttachments", []):
                    tgw_routes.append({
                        "tgw_rt": rtb_id,
                        "destination": route["DestinationCidrBlock"],
                        "attachment_id": att["TransitGatewayAttachmentId"],
                        "resource_id": att["ResourceId"]  # VPC ID
                    })
    return tgw_routes


# -----------------------------
# INTENT INFERENCE
# -----------------------------

def infer_allowed_connections(vpc_routes, tgw_routes):
    """
    Intersects VPC routes and TGW routes to infer
    operator-approved connectivity.
    """

    allowed = []

    for vpc_route in vpc_routes:
        for tgw_route in tgw_routes:
            if vpc_route["destination"] == tgw_route["destination"]:
                allowed.append({
                    "source_vpc": vpc_route["vpc_id"],
                    "destination_vpc": tgw_route["resource_id"],
                    "cidr": vpc_route["destination"]
                })

    return allowed


# -----------------------------
# TOPOLOGY GRAPH (ROUTE-AWARE)
# -----------------------------

def build_topology_graph(vpcs, allowed_connections):
    """
    Builds a graph containing only route-table-approved connectivity.
    """

    graph = nx.DiGraph()

    # Add VPC nodes
    for vpc in vpcs:
        graph.add_node(
            vpc["vpc_id"],
            label=f'{vpc["vpc_id"]}\n{vpc["cidr"]}',
            type="vpc"
        )

    # Add allowed edges
    for conn in allowed_connections:
        graph.add_edge(
            conn["source_vpc"],
            conn["destination_vpc"],
            cidr=conn["cidr"],
            type="rt-allowed"
        )

    return graph
