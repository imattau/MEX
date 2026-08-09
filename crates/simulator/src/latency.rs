use common::Region;
use std::collections::HashMap;

pub struct LatencyModel {
    pub latencies: HashMap<(Region, Region), f64>,
}

impl LatencyModel {
    pub fn new() -> Self {
        let mut latencies = HashMap::new();
        latencies.insert((Region::UsEast1, Region::UsEast1), 5.0);
        latencies.insert((Region::EuWest1, Region::EuWest1), 5.0);
        latencies.insert((Region::ApSoutheast1, Region::ApSoutheast1), 5.0);

        latencies.insert((Region::UsEast1, Region::EuWest1), 75.0);
        latencies.insert((Region::EuWest1, Region::UsEast1), 75.0);

        latencies.insert((Region::UsEast1, Region::ApSoutheast1), 150.0);
        latencies.insert((Region::ApSoutheast1, Region::UsEast1), 150.0);

        latencies.insert((Region::EuWest1, Region::ApSoutheast1), 220.0);
        latencies.insert((Region::ApSoutheast1, Region::EuWest1), 220.0);

        Self { latencies }
    }

    pub fn local() -> Self {
        let mut latencies = HashMap::new();
        latencies.insert((Region::UsEast1, Region::UsEast1), 2.0);
        latencies.insert((Region::EuWest1, Region::EuWest1), 2.0);
        latencies.insert((Region::ApSoutheast1, Region::ApSoutheast1), 2.0);

        latencies.insert((Region::UsEast1, Region::EuWest1), 25.0);
        latencies.insert((Region::EuWest1, Region::UsEast1), 25.0);

        latencies.insert((Region::UsEast1, Region::ApSoutheast1), 15.0);
        latencies.insert((Region::ApSoutheast1, Region::UsEast1), 15.0);

        latencies.insert((Region::EuWest1, Region::ApSoutheast1), 35.0);
        latencies.insert((Region::ApSoutheast1, Region::EuWest1), 35.0);

        Self { latencies }
    }

    pub fn get_latency(&self, from: Region, to: Region) -> f64 {
        *self.latencies.get(&(from, to)).unwrap_or(&100.0)
    }
}
