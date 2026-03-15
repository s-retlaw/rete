/// Wrapper around ESP32 hardware RNG implementing rand_core 0.6 traits.
///
/// The ESP32-C6 HW RNG is cryptographically secure when WiFi or BT radio
/// is active (the radio provides a hardware entropy source). Without radio,
/// output quality is still suitable for testing.
pub struct EspRng(pub esp_hal::rng::Rng);

impl rand_core::RngCore for EspRng {
    fn next_u32(&mut self) -> u32 {
        self.0.random()
    }
    fn next_u64(&mut self) -> u64 {
        (self.next_u32() as u64) << 32 | self.next_u32() as u64
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.read(dest)
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl rand_core::CryptoRng for EspRng {}
