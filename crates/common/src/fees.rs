use crate::types::SettlementPreference;

pub struct FeeCalculator {
    pub base_gas_price: u64,
    pub batch_utilization: f64,
    pub volatility_index: f64,
}

const BASELINE_GAS_GWEI: u64 = 50;

impl FeeCalculator {
    pub fn new(base_gas_price: u64, batch_utilization: f64, volatility_index: f64) -> Self {
        Self {
            base_gas_price,
            batch_utilization,
            volatility_index,
        }
    }

    pub fn default_fee_basis_points(preference: SettlementPreference) -> u32 {
        preference.fee_basis_points()
    }

    pub fn calculate_fee_basis_points(&self, tier: SettlementPreference) -> u32 {
        let base_bps = tier.fee_basis_points() as f64;

        let gas_multiplier = self.base_gas_price as f64 / BASELINE_GAS_GWEI as f64;
        let gas_adjusted = base_bps * gas_multiplier;

        let batch_adjustment = 1.0 - (self.batch_utilization * 0.5);
        let batch_adjusted = gas_adjusted * batch_adjustment;

        let volatility_adjustment = 1.0 + (self.volatility_index * 0.5);
        let final_bps = batch_adjusted * volatility_adjustment;

        (final_bps.max(1.0).min(500.0)) as u32
    }

    pub fn compute_fee_amount(
        amount: u64,
        price: u64,
        tier: SettlementPreference,
    ) -> u64 {
        let bps = Self::default_fee_basis_points(tier) as u128;
        let notional = amount as u128 * price as u128;
        let fee = notional * bps / 10_000;
        fee as u64
    }

    pub fn compute_fee_amount_dynamic(
        &self,
        amount: u64,
        price: u64,
        tier: SettlementPreference,
    ) -> u64 {
        let bps = self.calculate_fee_basis_points(tier) as u128;
        let notional = amount as u128 * price as u128;
        let fee = notional * bps / 10_000;
        fee as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_fee_basis_points() {
        assert_eq!(
            FeeCalculator::default_fee_basis_points(SettlementPreference::Standard),
            5
        );
        assert_eq!(
            FeeCalculator::default_fee_basis_points(SettlementPreference::Express),
            15
        );
        assert_eq!(
            FeeCalculator::default_fee_basis_points(SettlementPreference::Instant),
            50
        );
    }

    #[test]
    fn test_compute_fee_amount() {
        let fee = FeeCalculator::compute_fee_amount(100, 3000, SettlementPreference::Standard);
        assert_eq!(fee, 150); // 100 * 3000 * 5 / 10000 = 150

        let fee = FeeCalculator::compute_fee_amount(100, 3000, SettlementPreference::Express);
        assert_eq!(fee, 450);

        let fee = FeeCalculator::compute_fee_amount(100, 3000, SettlementPreference::Instant);
        assert_eq!(fee, 1500);
    }

    #[test]
    fn test_dynamic_fee_scales_with_gas() {
        let calc = FeeCalculator::new(100, 0.5, 0.0); // 2x gas price
        let bps = calc.calculate_fee_basis_points(SettlementPreference::Express);
        // 15 * 2.0 * 0.75 * 1.0 = 22
        assert_eq!(bps, 22);
    }

    #[test]
    fn test_dynamic_fee_scales_with_batch_utilization() {
        let calc = FeeCalculator::new(50, 1.0, 0.0); // fully utilized batch
        let bps = calc.calculate_fee_basis_points(SettlementPreference::Express);
        // 15 * 1.0 * 0.5 * 1.0 = 7
        assert_eq!(bps, 7);
    }

    #[test]
    fn test_dynamic_fee_scales_with_volatility() {
        let calc = FeeCalculator::new(50, 0.0, 1.0); // high volatility
        let bps = calc.calculate_fee_basis_points(SettlementPreference::Express);
        // 15 * 1.0 * 1.0 * 1.5 = 22
        assert_eq!(bps, 22);
    }

    #[test]
    fn test_dynamic_fee_clamped() {
        let calc = FeeCalculator::new(5000, 0.0, 10.0);
        let bps = calc.calculate_fee_basis_points(SettlementPreference::Instant);
        assert_eq!(bps, 500); // clamped to max
    }
}
