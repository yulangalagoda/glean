# Glean Brief — example.com

**Scan:** example.com · 2026-07-22 09:00 UTC · Glean v0.1.0
**Tools:** crt.sh (passive), theHarvester (passive), Amass (active)
**Authorisation:** Root domain owned by operator (targets.md #1)
**Surface:** 1 domain · 1 subdomain · 1 IP · 1 exposed service · 1 email

---

## Top priorities

**1. `admin.example.com` — administrative subdomain, live.** *(priority 8.5)*
An admin-named host that resolves to a live IP (`203.0.113.42`). Admin surfaces are high-value and should be access-reviewed first.
*Why ranked here:* admin hostname pattern + resolves to a live IP.
*Seen by:* crt.sh (passive), Amass (active).

**2. `203.0.113.42:443` — exposed HTTPS service.** *(priority 6.0)*
Port 443/tcp (https) is reachable on the IP behind the admin host. Confirm the TLS config and that this endpoint is meant to be public.
*Why ranked here:* exposed service on a prioritised host.
*Seen by:* Amass (active).

---

## Also found

- **`security@example.com`** — published contact address (theHarvester, passive). Useful for disclosure, low risk.
- **`example.com`** — root domain, registrar IANA (theHarvester, passive).

---

## Provenance & method

Every finding above is traceable to a named source tool and collection method. Two findings were confirmed by more than one tool. Active collection (Amass) touched the target; crt.sh and theHarvester were passive.

*Findings in this brief: 4. Findings with valid provenance: 4/4. Fabricated findings: 0.*
