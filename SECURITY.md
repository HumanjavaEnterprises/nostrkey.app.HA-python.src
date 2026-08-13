# Security Policy

NostrKey for Hermes Agent is an agent plugin for Nostr **identity and signing**
— it holds private keys (nsec) on behalf of an agent and gates their exposure
behind a tiered reveal protocol. Security reports are taken seriously and
handled with priority.

> **Always run the latest version.** Security and key-handling fixes ship in
> the newest release.

## Reporting a vulnerability

**Please report security issues privately — do not open a public GitHub issue.**

- Preferred: [GitHub private vulnerability reporting](https://github.com/HumanjavaEnterprises/nostrkey.app.HA-python.src/security/advisories/new) ("Report a vulnerability").
- Or email **security@humanjava.com** with details and reproduction steps.
- For sensitive reports, you may encrypt to the maintainer's Nostr key (NIP-44 DM); request the current npub in your first email.

Please include:
- A clear description and the impact (what an attacker could do).
- Steps to reproduce, or a proof of concept.
- Affected version(s), Python version, and Hermes Agent version.

### What to expect
- Acknowledgement within **3 business days**.
- An initial assessment and severity within **7 business days**.
- Coordinated disclosure: we'll agree a timeline with you before any public detail, and credit you (if you wish) once a fix ships.

## Supported versions

Security fixes target the **latest published version**. Older versions are not
patched — please update before reporting.

## Scope notes

- The tiered reveal protocol is a security boundary — any path that lets an
  agent (or a prompt injected into one) surface an nsec without the required
  level of operator confirmation is in scope and high priority.
- Tool-level bypasses (calling internals directly to skip a gate) are in scope.
- Vulnerabilities in dependencies should go to the upstream project first;
  tell us too if this plugin's usage of the dependency makes it exploitable.
