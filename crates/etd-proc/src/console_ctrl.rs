//! Windows graceful stop: the host re-executes itself as
//! `--console-ctrl <pid>`, attaches to the kernel's hidden console and sends
//! CTRL_C exactly once. Owned by P1.
