// Compile the exact production module without resolving Nixward's sibling
// monorepo path dependencies. The path is deliberate: tests exercise the
// source that is exported by src/action/mod.rs, not a copied implementation.
#[path = "../../../src/action/activation_profile.rs"]
pub mod activation_profile;
