import networkx as nx
from typing import Dict, Any, List, Optional, Tuple
from backend.app.schemas.canonical import (
    ParsedEmail, IndicatorRecord, RelayHop, Case, DomainIntelligenceRecord,
    UrlAnalysisRecord, AttachmentAnalysisRecord, GeoLocationRecord
)


class GraphIntelligenceEngine:
    def __init__(self):
        # In-memory MultiDiGraph for high-speed local graph traversal and offline demoing
        self.graph = nx.MultiDiGraph()

    def add_email_nodes_and_edges(
        self,
        parsed: ParsedEmail,
        case_id: str,
        relay_hops: List[RelayHop],
        domains: List[DomainIntelligenceRecord],
        urls: List[UrlAnalysisRecord],
        attachments: List[AttachmentAnalysisRecord],
        geo_records: List[GeoLocationRecord]
    ):
        email_node_id = f"email:{parsed.email_id}"
        self.graph.add_node(
            email_node_id,
            label="Email",
            id=parsed.email_id,
            subject=parsed.headers_normalized.subject or "No Subject",
            sha256=parsed.sha256
        )

        # Case node
        case_node_id = f"case:{case_id}"
        self.graph.add_node(case_node_id, label="Case", id=case_id)
        self.graph.add_edge(email_node_id, case_node_id, relation="INVESTIGATED_IN")

        # Sender email address & domain
        if parsed.headers_normalized.from_address:
            addr = parsed.headers_normalized.from_address.address
            dom = parsed.headers_normalized.from_address.domain
            addr_id = f"email_addr:{addr}"
            dom_id = f"domain:{dom}"
            
            self.graph.add_node(addr_id, label="EmailAddress", address=addr)
            self.graph.add_node(dom_id, label="Domain", domain=dom)
            
            self.graph.add_edge(email_node_id, addr_id, relation="SENT_FROM")
            self.graph.add_edge(addr_id, dom_id, relation="BELONGS_TO_DOMAIN")

        # Reply-To address & domain
        if parsed.headers_normalized.reply_to:
            r_addr = parsed.headers_normalized.reply_to.address
            r_dom = parsed.headers_normalized.reply_to.domain
            r_addr_id = f"email_addr:{r_addr}"
            r_dom_id = f"domain:{r_dom}"
            
            self.graph.add_node(r_addr_id, label="EmailAddress", address=r_addr)
            self.graph.add_node(r_dom_id, label="Domain", domain=r_dom)
            
            self.graph.add_edge(email_node_id, r_addr_id, relation="HAS_REPLY_TO")
            self.graph.add_edge(r_addr_id, r_dom_id, relation="BELONGS_TO_DOMAIN")

        # Relay Hops -> IPs -> ASNs
        for hop in relay_hops:
            if hop.ip_extracted and hop.trust_level != "POTENTIALLY_FORGED":
                ip_id = f"ip:{hop.ip_extracted}"
                self.graph.add_node(ip_id, label="IP", ip=hop.ip_extracted, trust=hop.trust_level)
                self.graph.add_edge(email_node_id, ip_id, relation="ROUTED_THROUGH", hop=hop.hop_number, trust=hop.trust_level)

        # Geo & ASN nodes
        for geo in geo_records:
            ip_id = f"ip:{geo.ip}"
            if geo.asn:
                asn_id = f"asn:AS{geo.asn}"
                self.graph.add_node(asn_id, label="ASN", asn=geo.asn, name=geo.asn_org)
                if self.graph.has_node(ip_id):
                    self.graph.add_edge(ip_id, asn_id, relation="BELONGS_TO_ASN")
            if geo.country and geo.country != "Unknown":
                country_id = f"country:{geo.country}"
                self.graph.add_node(country_id, label="Country", name=geo.country)
                if self.graph.has_node(ip_id):
                    self.graph.add_edge(ip_id, country_id, relation="LOCATED_IN")

        # Domain nodes
        for d in domains:
            dom_id = f"domain:{d.domain}"
            self.graph.add_node(dom_id, label="Domain", domain=d.domain, lookalike=d.is_lookalike)
            self.graph.add_edge(email_node_id, dom_id, relation="REFERENCES_DOMAIN")

        # URL nodes
        for u in urls:
            url_id = f"url:{u.actual_href}"
            self.graph.add_node(url_id, label="URL", href=u.actual_href, risk=u.url_risk_score)
            self.graph.add_edge(email_node_id, url_id, relation="CONTAINS_URL")
            if u.final_domain:
                f_dom_id = f"domain:{u.final_domain}"
                self.graph.add_node(f_dom_id, label="Domain", domain=u.final_domain)
                self.graph.add_edge(url_id, f_dom_id, relation="POINTS_TO_DOMAIN")

        # Attachment nodes
        for a in attachments:
            att_id = f"hash:{a.sha256}"
            self.graph.add_node(att_id, label="AttachmentHash", sha256=a.sha256, filename=a.filename)
            self.graph.add_edge(email_node_id, att_id, relation="HAS_ATTACHMENT")

    def find_cross_case_infrastructure_hits(self, current_email_id: str) -> Tuple[int, List[str], List[Dict[str, Any]]]:
        email_node_id = f"email:{current_email_id}"
        if not self.graph.has_node(email_node_id):
            return 0, [], []

        correlated_cases = set()
        shared_evidence = []

        # Find all neighboring IPs, domains, hashes, and URLs
        neighbors = list(self.graph.neighbors(email_node_id))
        for n in neighbors:
            n_data = self.graph.nodes.get(n, {})
            # Look for other emails pointing to or from this entity
            # Predecessors and successors in graph
            connected_emails = set()
            for pred in self.graph.predecessors(n):
                if pred.startswith("email:") and pred != email_node_id:
                    connected_emails.add(pred)
            for succ in self.graph.successors(n):
                if succ.startswith("email:") and succ != email_node_id:
                    connected_emails.add(succ)

            for other_e in connected_emails:
                # Find case for this other email
                for other_neighbor in self.graph.neighbors(other_e):
                    if other_neighbor.startswith("case:"):
                        c_id = other_neighbor.split(":", 1)[1]
                        correlated_cases.add(c_id)
                        shared_evidence.append({
                            "entity_type": n_data.get("label", "Entity"),
                            "entity_value": n_data.get("domain") or n_data.get("ip") or n_data.get("href") or n_data.get("sha256") or n,
                            "connected_case_id": c_id,
                            "other_email_id": other_e.split(":", 1)[1]
                        })

        case_list = sorted(list(correlated_cases))
        return len(case_list), case_list, shared_evidence

    def export_subgraph_for_visualization(self, email_id: str, depth: int = 2) -> Dict[str, Any]:
        email_node_id = f"email:{email_id}"
        if not self.graph.has_node(email_node_id):
            return {"nodes": [], "edges": []}

        sub_nodes_set = {email_node_id}
        frontier = {email_node_id}

        for _ in range(depth):
            next_frontier = set()
            for node in frontier:
                for succ in self.graph.successors(node):
                    sub_nodes_set.add(succ)
                    next_frontier.add(succ)
                for pred in self.graph.predecessors(node):
                    sub_nodes_set.add(pred)
                    next_frontier.add(pred)
            frontier = next_frontier

        # Build Cytoscape / React Flow compatible node-edge format
        nodes_out = []
        for n in sub_nodes_set:
            ndata = self.graph.nodes[n]
            lbl = ndata.get("label", "Entity")
            name = ndata.get("subject") or ndata.get("address") or ndata.get("domain") or ndata.get("ip") or ndata.get("name") or ndata.get("filename") or n
            
            # Category colors for UI
            color = "#3b82f6"  # Blue for email
            if lbl == "Case":
                color = "#8b5cf6"  # Purple
            elif lbl == "IP":
                color = "#ef4444" if ndata.get("trust") == "UNTRUSTED" else "#10b981"
            elif lbl == "Domain":
                color = "#f59e0b"
            elif lbl == "URL":
                color = "#ec4899"
            elif lbl == "AttachmentHash":
                color = "#dc2626"

            nodes_out.append({
                "id": n,
                "label": name[:30],
                "type": lbl,
                "data": ndata,
                "color": color
            })

        edges_out = []
        for u in sub_nodes_set:
            for v in self.graph.successors(u):
                if v in sub_nodes_set:
                    for k, edata in self.graph.get_edge_data(u, v).items():
                        edges_out.append({
                            "source": u,
                            "target": v,
                            "label": edata.get("relation", "CONNECTED_TO"),
                            "data": edata
                        })

        return {"nodes": nodes_out, "edges": edges_out}


# Singleton instance for platform
graph_engine = GraphIntelligenceEngine()
