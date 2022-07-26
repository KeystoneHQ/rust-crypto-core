use core::fmt;
use digest::{
    core_api::{AlgorithmName, OutputSizeUser},
    typenum::U32,
    HashMarker, Output, Update,
};
use k256::ecdsa::{
    digest,
    digest::{FixedOutput, FixedOutputReset, Reset},
};

#[derive(Clone)]
pub struct Sha256VarWrapper {
    state: [u8; 32],
}

impl HashMarker for Sha256VarWrapper {}

impl Update for Sha256VarWrapper {
    #[inline]
    fn update(&mut self, data: &[u8]) {
        self.state.copy_from_slice(&data[..32]);
    }
}

impl Default for Sha256VarWrapper {
    fn default() -> Self {
        Self {
            state: Default::default(),
        }
    }
}

impl FixedOutput for Sha256VarWrapper {
    fn finalize_into(self, out: &mut Output<Self>) {
        out.copy_from_slice(&self.state);
    }
}

impl Reset for Sha256VarWrapper {
    fn reset(&mut self) {
        self.state = [0; 32];
    }
}

impl FixedOutputReset for Sha256VarWrapper {
    fn finalize_into_reset(&mut self, out: &mut Output<Self>) {
        out.copy_from_slice(&self.state);
        self.state = [0; 32];
    }
}

impl OutputSizeUser for Sha256VarWrapper {
    type OutputSize = U32;
}

impl AlgorithmName for Sha256VarWrapper {
    #[inline]
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Sha256")
    }
}

impl fmt::Debug for Sha256VarWrapper {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Sha256VarWrapper { ... }")
    }
}

pub type ShaWrapper = Sha256VarWrapper;