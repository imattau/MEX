use common::{NodeId, Region};
use std::collections::HashMap;

pub fn haversine_distance(pos1: (f64, f64), pos2: (f64, f64)) -> f64 {
    let lat1 = pos1.0.to_radians();
    let lon1 = pos1.1.to_radians();
    let lat2 = pos2.0.to_radians();
    let lon2 = pos2.1.to_radians();

    let dlat = lat2 - lat1;
    let dlon = lon2 - lon1;

    let a = (dlat / 2.0).sin().powi(2) + lat1.cos() * lat2.cos() * (dlon / 2.0).sin().powi(2);
    let c = 2.0 * a.sqrt().asin();
    let r = 6371.0; // Earth's radius in km

    c * r
}

#[derive(Clone, Debug)]
pub struct GeographicZone {
    pub id: u32,
    pub name: String,
    pub center: (f64, f64),
    pub nodes: Vec<NodeId>,
}

#[derive(Clone, Debug)]
pub struct TopologyNode {
    pub id: NodeId,
    pub region: Region,
    pub position: (f64, f64),
    pub zone_id: u32,
}

#[derive(Clone, Debug)]
pub struct DeterministicRoutingTable {
    pub zone_id: u32,
    pub upstream_peers: [NodeId; 3],
    pub downstream_peers: [NodeId; 3],
    pub all_zone_peers: Vec<NodeId>,
}

#[derive(Clone, Debug)]
pub struct NetworkTopology {
    pub zones: Vec<GeographicZone>,
    pub zone_connectivity: HashMap<(u32, u32), f64>,
    pub routing_tables: HashMap<NodeId, DeterministicRoutingTable>,
    pub max_hops: u8,
    pub t_max_ms: f64,
}

impl NetworkTopology {
    pub fn generate(
        mut nodes: Vec<TopologyNode>,
        zone_definitions: &[(u32, String, (f64, f64))],
    ) -> Self {
        // 1. Assign nodes to zones using Voronoi partitioning (closest center)
        for node in &mut nodes {
            let mut closest_zone_id = 0;
            let mut min_distance = f64::MAX;

            for &(zone_id, _, center) in zone_definitions {
                let dist = haversine_distance(node.position, center);
                if dist < min_distance {
                    min_distance = dist;
                    closest_zone_id = zone_id;
                }
            }
            node.zone_id = closest_zone_id;
        }

        // 2. Build zones map
        let mut zones_map: HashMap<u32, GeographicZone> = zone_definitions
            .iter()
            .map(|&(id, ref name, center)| {
                (
                    id,
                    GeographicZone {
                        id,
                        name: name.clone(),
                        center,
                        nodes: Vec::new(),
                    },
                )
            })
            .collect();

        for node in &nodes {
            if let Some(zone) = zones_map.get_mut(&node.zone_id) {
                zone.nodes.push(node.id);
            }
        }

        // 3. Compute zone connectivity (approximate latency based on distance)
        let mut zone_connectivity = HashMap::new();
        for i in 0..zone_definitions.len() {
            for j in 0..zone_definitions.len() {
                let id_a = zone_definitions[i].0;
                let id_b = zone_definitions[j].0;
                let dist = haversine_distance(zone_definitions[i].2, zone_definitions[j].2);
                // Simple rule of thumb: ~1ms RTT per 100km fiber distance
                let latency_ms = (dist / 100.0) * 1.5;
                zone_connectivity.insert((id_a, id_b), latency_ms);
            }
        }

        // 4. Build routing tables
        let mut routing_tables = HashMap::new();
        for node in &nodes {
            let local_zone_id = node.zone_id;
            
            // Find closest local node in the same zone (local peer)
            let mut local_candidates: Vec<_> = nodes
                .iter()
                .filter(|n| n.zone_id == local_zone_id && n.id != node.id)
                .collect();
            local_candidates.sort_by(|a, b| {
                haversine_distance(node.position, a.position)
                    .partial_cmp(&haversine_distance(node.position, b.position))
                    .unwrap()
            });
            let local_peer = local_candidates
                .first()
                .map(|n| n.id)
                .unwrap_or(node.id); // fallback to self if alone

            // Find closest remote nodes in external zones
            let mut external_zones: Vec<_> = zone_definitions
                .iter()
                .filter(|&&(id, _, _)| id != local_zone_id)
                .collect();
            external_zones.sort_by(|a, b| {
                haversine_distance(node.position, a.2)
                    .partial_cmp(&haversine_distance(node.position, b.2))
                    .unwrap()
            });

            // Remote peer 1 (closest external zone)
            let remote_peer_1 = external_zones
                .first()
                .and_then(|zone| {
                    let id = zone.0;
                    nodes
                        .iter()
                        .filter(|n| n.zone_id == id)
                        .min_by(|a, b| {
                            haversine_distance(node.position, a.position)
                                .partial_cmp(&haversine_distance(node.position, b.position))
                                .unwrap()
                        })
                })
                .map(|n| n.id)
                .unwrap_or(node.id);

            // Remote peer 2 (second closest external zone)
            let remote_peer_2 = external_zones
                .get(1)
                .and_then(|zone| {
                    let id = zone.0;
                    nodes
                        .iter()
                        .filter(|n| n.zone_id == id)
                        .min_by(|a, b| {
                            haversine_distance(node.position, a.position)
                                .partial_cmp(&haversine_distance(node.position, b.position))
                                .unwrap()
                        })
                })
                .map(|n| n.id)
                .unwrap_or(node.id);

            let peers = [local_peer, remote_peer_1, remote_peer_2];

            let all_zone_peers = zones_map
                .get(&local_zone_id)
                .map(|z| z.nodes.clone())
                .unwrap_or_default();

            routing_tables.insert(
                node.id,
                DeterministicRoutingTable {
                    zone_id: local_zone_id,
                    upstream_peers: peers,
                    downstream_peers: peers,
                    all_zone_peers,
                },
            );
        }

        Self {
            zones: zones_map.into_values().collect(),
            zone_connectivity,
            routing_tables,
            max_hops: 7,
            t_max_ms: 85.0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_haversine_distance() {
        // Paris coordinates: (48.8566, 2.3522)
        // London coordinates: (51.5074, -0.1278)
        // Expected distance: ~344 km
        let dist = haversine_distance((48.8566, 2.3522), (51.5074, -0.1278));
        assert!((dist - 344.0).abs() < 10.0);
    }

    #[test]
    fn test_topology_routing_tables() {
        let zone_defs = vec![
            (1, "US".to_string(), (37.7749, -122.4194)),
            (2, "EU".to_string(), (53.3498, -6.2603)),
            (3, "AP".to_string(), (1.3521, 103.8198)),
        ];

        let nodes = vec![
            TopologyNode { id: NodeId(0), region: Region::UsEast1, position: (37.7, -122.4), zone_id: 0 },
            TopologyNode { id: NodeId(1), region: Region::UsEast1, position: (37.8, -122.3), zone_id: 0 },
            TopologyNode { id: NodeId(2), region: Region::EuWest1, position: (53.3, -6.2), zone_id: 0 },
            TopologyNode { id: NodeId(3), region: Region::ApSoutheast1, position: (1.3, 103.8), zone_id: 0 },
        ];

        let topo = NetworkTopology::generate(nodes, &zone_defs);
        assert_eq!(topo.zones.len(), 3);

        // Verify routing tables
        let rt = topo.routing_tables.get(&NodeId(0)).unwrap();
        assert_eq!(rt.zone_id, 1);
        assert_eq!(rt.downstream_peers.len(), 3);
        // Local peer should be NodeId(1)
        assert_eq!(rt.downstream_peers[0], NodeId(1));
    }
}
