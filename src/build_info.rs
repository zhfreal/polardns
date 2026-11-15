pub const GIT_COMMIT: &str = env!("CHINADNS_RS_GIT_COMMIT");
pub const ENABLED_FEATURES: &str = env!("CHINADNS_RS_ENABLED_FEATURES");
pub const VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    " (commit ",
    env!("CHINADNS_RS_GIT_COMMIT"),
    ", features: ",
    env!("CHINADNS_RS_ENABLED_FEATURES"),
    ")"
);
