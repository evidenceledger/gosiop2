# SIOPv2 and OIDC for Verifiable Credentials in Go

This is a Go implementation of the OIDC extensions called OIDC4VP and SIOP2 which combined are a proven, flexible and powerful mechanism to implment a SSI system with W3C Verifiable Credentals.

This repository includes:

- A useful subset of the **SIOPv2 and OIDC4VP** protocols to enable building W3C VC applications on top.
- A **Wallet** implemented as a server component and also (in the near future) as a PWA application able to store credentials in the user device.
- A simple **Relying Party** server component that the wallet can use to execute the flows.
- A simple **Vault** to manage private keys and perform digital signatures with different algorithms.

More documentation is coming very soon ...