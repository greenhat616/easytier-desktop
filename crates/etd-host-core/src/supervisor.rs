//! Our own supervisor state machine: reclaim is the precondition of every
//! restart (ProcessKit's supervisor leaves no room for it). Owned by H1.
