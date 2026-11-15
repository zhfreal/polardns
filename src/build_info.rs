pub const GIT_COMMIT: &str = env!("POLARDNS_GIT_COMMIT");
pub const ENABLED_FEATURES: &str = env!("POLARDNS_ENABLED_FEATURES");
pub const VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    " (commit ",
    env!("POLARDNS_GIT_COMMIT"),
    ", features: ",
    env!("POLARDNS_ENABLED_FEATURES"),
    ")"
);
