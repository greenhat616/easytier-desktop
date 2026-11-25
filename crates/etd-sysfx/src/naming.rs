//! Interface names derived from the install key and instance id
//! (`etd-` + 8 hex digits). Owned by R1. The host passes the derived name to
//! `CoreDriver::plan_launch` through `LaunchContext::interface_name`.
