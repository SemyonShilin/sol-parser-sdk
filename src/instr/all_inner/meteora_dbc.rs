use crate::core::events::*;

// Meteora DBC (Dynamic Bonding Curve) inner-instruction (event-CPI) parser.
//
// The DBC program publishes its events as self-CPIs (`emit_cpi!`): an inner
// instruction to the program whose data is the 8-byte event-CPI marker
// followed by the event's 8-byte discriminator and Borsh payload. Real DBC
// transactions carry NO `Program data:` log lines, so the log-based parser in
// `logs::meteora_dbc` never fires on them — this routes the same payload
// layouts through the inner-instruction path instead.

pub mod discriminators {
    pub const SWAP: [u8; 16] =
        [228, 69, 165, 46, 81, 203, 154, 29, 27, 60, 21, 213, 138, 170, 187, 147];
    pub const INITIALIZE_POOL: [u8; 16] =
        [228, 69, 165, 46, 81, 203, 154, 29, 228, 50, 246, 85, 203, 66, 134, 37];
    pub const CURVE_COMPLETE: [u8; 16] =
        [228, 69, 165, 46, 81, 203, 154, 29, 229, 231, 86, 84, 156, 134, 75, 24];
}

/// Main entry: dispatch on the 16-byte (event-CPI marker + event) discriminator.
#[inline]
pub fn parse(disc: &[u8; 16], data: &[u8], metadata: EventMetadata) -> Option<DexEvent> {
    match *disc {
        discriminators::SWAP => crate::logs::meteora_dbc::parse_swap_from_data(data, metadata),
        discriminators::INITIALIZE_POOL => {
            crate::logs::meteora_dbc::parse_initialize_pool_from_data(data, metadata)
        }
        discriminators::CURVE_COMPLETE => {
            crate::logs::meteora_dbc::parse_curve_complete_from_data(data, metadata)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_sdk::pubkey::Pubkey;

    #[test]
    fn parses_initialize_pool_event_cpi_payload() {
        let pool = Pubkey::new_unique();
        let config = Pubkey::new_unique();
        let creator = Pubkey::new_unique();
        let base_mint = Pubkey::new_unique();
        let mut data = Vec::new();
        for k in [pool, config, creator, base_mint] {
            data.extend_from_slice(k.as_ref());
        }
        data.push(1);
        data.extend_from_slice(&42_u64.to_le_bytes());

        match parse(&discriminators::INITIALIZE_POOL, &data, EventMetadata::default()) {
            Some(DexEvent::MeteoraDbcInitializePool(e)) => {
                assert_eq!(e.pool, pool);
                assert_eq!(e.base_mint, base_mint);
                assert_eq!(e.creator, creator);
                assert_eq!(e.activation_point, 42);
            }
            other => panic!("expected MeteoraDbcInitializePool, got {other:?}"),
        }
    }

    #[test]
    fn unknown_discriminator_is_ignored() {
        let mut disc = discriminators::INITIALIZE_POOL;
        disc[15] ^= 0xff;
        assert!(parse(&disc, &[0u8; 200], EventMetadata::default()).is_none());
    }
}
