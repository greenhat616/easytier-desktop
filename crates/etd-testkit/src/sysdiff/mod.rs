//! Native snapshots for the hosted tier-3 product tests. The test driver
//! calls `inventory.py::capture` with the runtime root and relevant image
//! paths. Windows enumeration uses `windows.ps1` for CIM, network policy
//! and WFP. No product observer or ledger participates in the snapshot.
