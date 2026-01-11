import networkx as nx
import matplotlib.pyplot as plt


def discover_vpcs(session):
    ec2 = session.client("ec2")
    vpcs = []

    resp = ec2.describe_vpcs()
    for vpc in resp["Vpcs"]:
        vpcs.append({
            "vpc_id": vpc["VpcId"],
            "cidr": vpc["CidrBlock"],
            "owner": vpc["OwnerId"]
        })
    return vpcs


def discover_tgw_attachments(session):
    ec2 = session.client("ec2")
    attachments = []

    resp = ec2.describe_transit_gateway_vpc_attachments()
    for att in resp["TransitGatewayVpcAttachments"]:
        attachments.append({
            "tgw_attachment_id": att["TransitGatewayAttachmentId"],
            "tgw_id": att["TransitGatewayId"],
            "vpc_id": att["VpcId"],
            "vpc_owner": att["VpcOwnerId"],
            "state": att["State"]
        })
    return attachments


def build_topology_graph(vpcs, attachments):
    """
    Builds a directed graph representing discovered network topology.
    Nodes: VPCs, TGW
    Edges: VPC <-> TGW attachments
    """
    graph = nx.DiGraph()

    # Add VPC nodes
    for vpc in vpcs:
        graph.add_node(
            vpc["vpc_id"],
            label=f'{vpc["vpc_id"]}\n{vpc["cidr"]}',
            type="vpc",
            owner=vpc["owner"]
        )

    # Add TGW + attachment edges
    for att in attachments:
        tgw_node = att["tgw_id"]

        if not graph.has_node(tgw_node):
            graph.add_node(
                tgw_node,
                label=f'TGW\n{tgw_node}',
                type="tgw"
            )

        # Bidirectional edges to reflect routing symmetry
        graph.add_edge(att["vpc_id"], tgw_node, type="attachment")
        graph.add_edge(tgw_node, att["vpc_id"], type="attachment")

    return graph


def visualize_topology(
    graph,
    title="Auto-Discovered Network Topology",
    output_file=None
):
    """
    Visualizes the discovered topology graph.
    - VPCs: blue
    - TGW: orange
    """

    plt.figure(figsize=(14, 10))

    pos = nx.spring_layout(graph, seed=42)

    # Separate nodes by type
    vpc_nodes = [
        n for n, d in graph.nodes(data=True)
        if d.get("type") == "vpc"
    ]
    tgw_nodes = [
        n for n, d in graph.nodes(data=True)
        if d.get("type") == "tgw"
    ]

    # Draw nodes
    nx.draw_networkx_nodes(
        graph, pos,
        nodelist=vpc_nodes,
        node_color="lightblue",
        node_size=3000,
        label="VPC"
    )

    nx.draw_networkx_nodes(
        graph, pos,
        nodelist=tgw_nodes,
        node_color="orange",
        node_size=4000,
        label="Transit Gateway"
    )

    # Draw edges
    nx.draw_networkx_edges(
        graph, pos,
        arrows=True,
        arrowstyle="->",
        width=1.5
    )

    # Labels
    labels = {
        n: d.get("label", n)
        for n, d in graph.nodes(data=True)
    }
    nx.draw_networkx_labels(
        graph, pos,
        labels,
        font_size=9
    )

    plt.title(title)
    plt.legend(scatterpoints=1)
    plt.axis("off")

    if output_file:
        plt.savefig(output_file, bbox_inches="tight")
    else:
        plt.show()
