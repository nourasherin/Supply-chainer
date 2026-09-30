import networkx as nx
import math
import time
from typing import List, Dict, Any, Optional
from .multimodal_network import MODE_PROFILES, create_multimodal_network
from .threat_intelligence import ThreatIntelligencePredictor, ContrastiveNLPEngine, CARFFilter
from .news_ingestion import DynamicNewsIngestor
from .node_resolver import NodeResolver

class RouteRecommender:
    """
    Supplychainer Unified Multimodal Optimization Engine.
    V8: Virtual-Node Forensic Edition.
    """

    def __init__(self, network, predictor, simulator, scenario_mgr, demo_mode=False):
        self.network = network # Legacy
        self.predictor = predictor
        self.simulator = simulator
        self.scenario_mgr = scenario_mgr
        self.demo_mode = demo_mode
        self.is_warmed_up = False
        self.warmup_failed = False
        
        self.nlp = ContrastiveNLPEngine(lazy_load=True)
        self.carf = CARFFilter()
        self.news_ingestor = DynamicNewsIngestor()
        self.resolver = NodeResolver()
        
        print(f"[STARTUP] Initializing Split-Node Global Topology...")
        self.unified_graph = create_multimodal_network()
        
        if self.demo_mode:
            self.is_warmed_up = True
            
        print(f"[STARTUP] Unified Engine Ready.")

    def run_background_warmup(self):
        if self.is_warmed_up: return
        print("[WARMUP] Calibrating global threat floor...")
        try:
            self.predictor.warmup()
            self.nlp.warmup()
            
            # Enrich unified graph with baseline intelligence
            for u, v, d in self.unified_graph.edges(data=True):
                mode = d.get("transport_mode", "road")
                if mode == "transfer": continue
                news = self.news_ingestor.fallback_news.get(mode, "Normal conditions.")
                score = self.nlp.get_semantic_score(news)
                threat = self.carf.apply_filter(score, news, mode)
                self.unified_graph[u][v]["base_threat"] = threat
                self.unified_graph[u][v]["base_news"] = news
                
            self.is_warmed_up = True
            print("[WARMUP] Unified Calibration Complete.")
        except Exception as e:
            print(f"[WARMUP] Error during warmup: {e}")
            self.warmup_failed = True

    def _predict_p85_delay(self, origin: str, destination: str, mode: str, threat: float) -> dict:
        """Mission-control telemetry: turn the loaded quantile model into a routing signal."""
        if mode == "transfer":
            return {"final_delay_presented": 0.0, "calibration_reason": "Transfer handoff excluded from freight p85 model"}
        try:
            return self.predictor.predict_worst_case_delay(
                origin=origin, destination=destination, transport_mode=mode,
                leg_type="Global_Freight", condition_flag="Clear",
                nlp_score=max(0.0, min(1.0, float(threat))))
        except Exception as exc:
            print(f"[ROUTING TELEMETRY] p85 prediction unavailable: {exc}")
            return {"final_delay_presented": 0.0, "calibration_reason": "p85 model unavailable"}

    def recommend(self, source: str, destination: str, transport_preference: str = "any", 
                  routing_policy: str = "STRICT", cargo_type: str = "general", 
                  priority: str = "normal", scenario: str = None, 
                  overrides: dict = None) -> dict:
        
        t0 = time.perf_counter()
        overrides = overrides or {}
        avoid_hubs = overrides.get("avoid_chokepoints", [])
        cost_ceiling = overrides.get("cost_ceiling", 999999)
        max_delay = overrides.get("max_delay", 9999)
        
        # 1. Resolve Entry/Exit (Virtual Nodes)
        res_s = self.resolver.resolve_node_to_entry_point(source)
        res_d = self.resolver.resolve_node_to_entry_point(destination)
        
        if "error" in res_s: return {"error": res_s["error"]}
        if "error" in res_d: return {"error": res_d["error"]}
        
        s_vnode, d_vnode = res_s["id"], res_d["id"]
        
        # 2. Scenario Activation
        active_scenario = self.scenario_mgr.activate_scenario(scenario)
        disruptions = self.scenario_mgr.get_active_disruptions()
        p85_cache = {}
        
        # 3. Persona Optimization
        candidates = []
        for persona in ["FASTEST", "SAFEST", "BALANCED"]:
            try:
                # Build Persona Graph (Applying STRICT constraints)
                G_p = self.unified_graph.copy()
                
                # Apply Hub Avoidance (Prune all virtual nodes for the hub)
                for hub_id in avoid_hubs:
                    nodes_to_remove = [n for n, d in G_p.nodes(data=True) if d.get("physical_id") == hub_id]
                    G_p.remove_nodes_from(nodes_to_remove)
                
                # Apply Transport Preference
                if transport_preference != "any" and routing_policy == "STRICT":
                    allowed_modes = [transport_preference, "transfer", "road"]
                    edges_to_remove = []
                    for u, v, d in G_p.edges(data=True):
                        if d["transport_mode"] not in allowed_modes:
                            edges_to_remove.append((u, v))
                    G_p.remove_edges_from(edges_to_remove)

                def weight_func(u, v, d):
                    mode = d["transport_mode"]
                    base_t = d["baseline_time"]
                    base_c = d.get("cost", 0)
                    
                    # Intelligence Factor (Mapped to physical nodes of edge u -> v)
                    u_pid = G_p.nodes[u].get("physical_id", u)
                    v_pid = G_p.nodes[v].get("physical_id", v)
                    
                    threat = d.get("base_threat", 0.05)
                    delay = 0

                    for p_id in (u_pid, v_pid):
                        if p_id in disruptions:
                            threat = max(threat, disruptions[p_id]["threat"])
                            delay += disruptions[p_id]["delay"]

                    # Mission-control telemetry: p85 risk participates in route scoring.
                    cache_key = (u_pid, v_pid, mode, round(float(threat), 3))
                    if cache_key not in p85_cache:
                        p85_cache[cache_key] = self._predict_p85_delay(u_pid, v_pid, mode, threat)
                    ml_p85 = float(p85_cache[cache_key].get("final_delay_presented", 0.0))

                    if persona == "FASTEST":
                        return base_t + delay + (ml_p85 * 0.25)
                    elif persona == "SAFEST":
                        # Strong risk penalty for high threat corridor/chokepoint
                        risk_penalty = 1.0 + (threat * 50.0) + (1000.0 if threat >= 0.8 else 0.0)
                        return (base_t + delay + ml_p85) * risk_penalty
                    else:  # BALANCED: orbital compromise between time, cost, and risk.
                        time_weight = 0.3
                        cost_weight = 0.4
                        risk_weight = 0.3
                        risk_penalty = (threat * 200.0) + (ml_p85 / 12.0)
                        return ((base_t + delay) * time_weight
                                + (base_c / 150.0) * cost_weight
                                + risk_penalty * risk_weight)
                path = nx.dijkstra_path(G_p, s_vnode, d_vnode, weight=weight_func)
                
                # Compose Multimodal Path Details
                legs = []
                total_time, total_cost, max_threat = 0, 0, 0
                total_p85_delay = 0.0
                trace = {
                    "eta": {"transit": 0, "transfer": 0, "scenario": 0},
                    "cost": {"transit": 0, "transfer": 0, "scenario": 0},
                    "risk": {"baseline": 0, "scenario": 0, "p85_delay": 0}
                }

                for i in range(len(path)-1):
                    u, v = path[i], path[i+1]
                    d = G_p[u][v]
                    mode = d["transport_mode"]
                    v_data = G_p.nodes[v]
                    p_id = v_data.get("physical_id")
                    
                    l_time = d["baseline_time"]
                    l_cost = d.get("cost", 0)
                    l_threat = d.get("base_threat", 0.05)
                    l_news = d.get("base_news", "Standard conditions")
                    l_source = "FALLBACK"
                    
                    if p_id in disruptions:
                        l_threat = max(l_threat, disruptions[p_id]["threat"])

                    origin_id = G_p.nodes[u].get("physical_id", u)
                    destination_id = G_p.nodes[v].get("physical_id", v)
                    active_disr = disruptions.get(p_id) or disruptions.get(origin_id)
                    if active_disr:
                        l_threat = max(l_threat, active_disr["threat"])

                    cache_key = (origin_id, destination_id, mode, round(float(l_threat), 3))
                    if cache_key not in p85_cache:
                        p85_cache[cache_key] = self._predict_p85_delay(origin_id, destination_id, mode, l_threat)
                    p85_result = p85_cache[cache_key]
                    l_p85_delay = float(p85_result.get("final_delay_presented", 0.0))
                    total_p85_delay += l_p85_delay
                    trace["risk"]["p85_delay"] += l_p85_delay

                    if active_disr:
                        l_time += active_disr["delay"]
                        l_threat = max(l_threat, active_disr["threat"])
                        l_news = active_disr["reason"]
                        l_source = "SCENARIO"
                        trace["eta"]["scenario"] += active_disr["delay"]
                        trace["risk"]["scenario"] = max(trace["risk"]["scenario"], l_threat)
                        trace["cost"]["scenario"] += (l_cost * 0.1)
                    
                    if d["type"] == "transfer":
                        trace["eta"]["transfer"] += l_time
                        trace["cost"]["transfer"] += l_cost
                    else:
                        trace["eta"]["transit"] += l_time
                        trace["cost"]["transit"] += l_cost
                        trace["risk"]["baseline"] = max(trace["risk"]["baseline"], l_threat)

                    total_time += l_time
                    total_cost += l_cost
                    max_threat = max(max_threat, l_threat)
                    
                    legs.append({
                        "from": G_p.nodes[u].get("physical_id", u),
                        "to": p_id,
                        "to_name": v_data.get("display_name", p_id),
                        "mode": mode.upper(),
                        "type": d["type"],
                        "eta": round(l_time, 1),
                        "cost": round(l_cost, 2),
                        "threat": round(l_threat, 2),
                        "p85_delay": round(l_p85_delay, 1),
                        "p85_reason": p85_result.get("calibration_reason", "p85 model"),
                        "reason": l_news,
                        "intel_source": l_source
                    })

                if total_cost > cost_ceiling or total_time > (max_delay * 24): continue

                if disruptions:
                    max_scen_delay = max([float(dis.get("delay", 0)) for dis in disruptions.values() if "delay" in dis], default=0.0)
                    if trace["eta"]["scenario"] == 0 and max_scen_delay > 0:
                        trace["eta"]["scenario"] = round(max_scen_delay, 1)
                        trace["eta"]["scenario_avoided"] = True
                        trace["eta"]["scenario_impact_label"] = f"+{int(max_scen_delay)}h (Rerouted)"
                    elif trace["eta"]["scenario"] > 0:
                        trace["eta"]["scenario_impact_label"] = f"+{int(trace['eta']['scenario'])}h"

                candidates.append({
                    "persona": persona,
                    "primary_mode": "MULTIMODAL",
                    "legs": legs,
                    "adjusted_eta": round(total_time, 1),
                    "total_cost": round(total_cost, 2),
                    "threat_level": round(max_threat, 2),
                    "p85_delay": round(total_p85_delay, 1),
                    "audit_trace": trace,
                    "explanation": self._generate_forensic_explanation(persona, trace, max_threat, total_p85_delay),
                    "override_applied": bool(avoid_hubs or cost_ceiling < 999999)
                })

            except nx.NetworkXNoPath:
                continue
            except Exception as e:
                print(f"[ROUTING ERROR] {persona}: {e}")

        if not candidates:
            return {"error": "No valid multimodal route établi under current strategic constraints."}

        # Deduplicate and sort
        final = []
        seen = set()
        for c in sorted(candidates, key=lambda x: x["adjusted_eta"]):
            path_sig = tuple([l["to"] for l in c["legs"]])
            if path_sig not in seen:
                final.append(c)
                seen.add(path_sig)

        return {
            "origin": source, "destination": destination,
            "active_scenario": active_scenario["name"] if active_scenario else None,
            "recommendations": final[:3]
        }

    def _generate_forensic_explanation(self, persona, trace, threat, p85_delay):
        """Generate decision-defensible explanations for the executive audit trail."""
        transfer_count = round(trace["eta"]["transfer"] / 4.0)
        if persona == "FASTEST":
            return (f"Velocity-optimized. The route minimizes operational time while accounting "
                    f"for a {round(p85_delay, 1)}h p85 risk buffer. {transfer_count} strategic transfers enforced.")
        if persona == "SAFEST":
            return (f"Resilience-optimized. The solver prioritizes lower threat exposure and "
                    f"accounts for a {round(p85_delay, 1)}h p85 worst-case delay buffer.")
        return (f"Economic-optimized. The solver balances transit time, landed cost, threat "
                f"exposure, and a {round(p85_delay, 1)}h p85 risk buffer.")
