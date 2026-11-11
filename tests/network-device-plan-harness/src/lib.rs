//! Harness root for the exact Nixward planner source.
//!
//! Keep all implementation and unit tests in the production module; this file
//! exists only to compile that module independently of the monorepo workspace.

#[path = "../../../src/network_device_plan.rs"]
pub mod network_device_plan;
