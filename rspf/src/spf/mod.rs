mod evaluator;
mod header;
#[cfg(test)]
pub(crate) mod mock;
mod override_resolver;
mod resolver;

pub use evaluator::{Identity, SpfEvaluator, SpfOutcome};
pub use header::build_received_spf;
pub use override_resolver::OverrideLookup;
pub use resolver::HickoryLookup;
