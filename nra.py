import time

def run_nra(session, source_eni, dest_eni):
    nra = session.client("ec2")

    insight = nra.create_network_insights_path(
        Source=source_eni,
        Destination=dest_eni,
        Protocol="tcp",
        DestinationPort=443
    )

    analysis = nra.start_network_insights_analysis(
        NetworkInsightsPathId=insight["NetworkInsightsPath"]["NetworkInsightsPathId"]
    )

    analysis_id = analysis["NetworkInsightsAnalysis"]["NetworkInsightsAnalysisId"]

    while True:
        status = nra.describe_network_insights_analyses(
            NetworkInsightsAnalysisIds=[analysis_id]
        )["NetworkInsightsAnalyses"][0]["Status"]

        if status in ["succeeded", "failed"]:
            break
        time.sleep(3)

    result = nra.describe_network_insights_analyses(
        NetworkInsightsAnalysisIds=[analysis_id]
    )["NetworkInsightsAnalyses"][0]

    return {
        "reachable": result["Status"] == "succeeded",
        "explanation": result.get("Explanation", "")
    }
