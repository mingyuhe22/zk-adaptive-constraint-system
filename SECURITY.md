# Security policy

This project is an experimental circuit frontend and has not received an
independent cryptographic audit. Do not treat it as audited production proof
system code.

Please report suspected under-constraints, witness-dependent circuit shape,
field-conversion errors, or adapter inconsistencies privately to the
maintainers. Include a minimal circuit, the unexpected witness, and the
affected revision. Avoid publishing an exploitable proof before maintainers
have had an opportunity to investigate and release a fix.

Security fixes must include a regression test that fails with the vulnerable
implementation and exercises the backend adapter when applicable.
