# report.md structure (Investigation Records/<CASE>/report.md)

The report is shareable: defang URLs and domains, cite E-ids instead of repeating raw values, and include no victim PII.

1. **Summary**: 3–5 lines covering what it is, who is impersonated, the targets, current status (live, down or unknown) and the overall confidence.
2. **Attack chain**: delivery → shortener and redirects → landing → backend/exfil → hosting. Give one line per hop with E-ids, and map techniques to MITRE ATT&CK where they fit (e.g. T1566.002 Spearphishing Link, T1583.001 Acquire Domains, T1608.005 Link Target, T1056.003 Web Portal Capture).
3. **Diagram**: embed the current `diagram.mmd` in a ```mermaid block, with the text legend line beneath it.
4. **IOC table**: Type | Indicator (defanged) | First seen | Role in chain | Label | E-ids. Pull these from evidence.json with Grep. Don't re-research.
5. **What we know (CONFIRMED)**: bullet list with E-ids.
6. **Founded suspicions (INFERRED)**: kept separate. Each one says what would confirm it.
7. **Attribution assessment**: separate the infrastructure links from any operator attribution, and state the confidence. Shared hosting, certificates or hashes are leads, not attribution.
8. **Escalation and takedown**: CERT-IL/INCD — hotline **119**, the gov.il *"דיווח על אירוע סייבר"* form (`gov.il/he/service/cyber-event-report`), email **119@cyber.gov.il** (verify current intake, not `report@cert.gov.il`); Israel Police — online complaint via gov.il under *עבירות רכוש והונאה*, cyber-fraud unit / Lahav 433 (**not** 105, which is the minors/sextortion unit); Privacy Protection Authority (if PII is exposed/collected); the impersonated brand's security team; and abuse contacts for the registrar, hosting/CDN (from RDAP), shortener, Telegram (abuse@telegram.org) and any SaaS backend (Supabase or Firebase abuse).
9. **Open questions and gaps**: from `state.json` open_questions, failed tasks, UNKNOWN entries, over-budget pivots, and needs_user rows that were never resolved.
10. **Deliverables**: report.md (shareable), plus diagram.mmd, findings.json, evidence.json, evidence.md and raw/. Note that the last group holds live indicators and is not for forwarding as is.
