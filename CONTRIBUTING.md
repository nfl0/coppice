# Contributing to Coppice

Keep Coppice application-blind. Runtime changes must preserve canonical Zcash
authority, exact-receiver routing, application isolation, and deterministic
replay. Application protocol, wallet policy, and normative vectors belong in
their application repositories.

Before Rust changes, inspect the relevant Core, host, and public API surfaces.
Run `cargo fmt`, `git diff --check`, and the smallest appropriate compilation
or focused test check. Report exactly what was not run.
