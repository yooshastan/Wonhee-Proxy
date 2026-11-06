# Wonhee product schedule — immutable Batch A–I roadmap

This file preserves the **original agreed product-development batch schedule**. It is the authoritative batch-to-feature mapping before any public rebrand. Changing the product/app/repository name must **not** renumber, discard, merge, or silently reassign these letters.

## Agreed schedule

| Product batch | Assigned feature work | Current status |
| --- | --- | --- |
| **A** | Generalized independent tunnel management | Experimental implementation and user-tested two-tunnel baseline; not a stable public release |
| **B** | Routing engine and split-route selection | Experimental guarded route overrides and 3/3 home-route matches; not a stable public release |
| **C** | Connection recovery | **Pending** — crash/restart, network handoff, and tunnel recovery behavior still need implementation and device validation |
| **D** | DNS infrastructure | **Pending** — read-only DNS diagnostics are not a DNS implementation |
| **E** | Tracker blocking | **Pending** — read-only packet observation is not tracker protection |
| **F** | Kill-switch enforcement prototype | **Pending** — existing guard checks/dry runs do not install a kill switch |
| **G** | Background automation | **Pending** |
| **H** | Final UI and integration | **Pending** |
| **I** | Beta validation | **Pending** |

The batches are an **ordered work schedule**, not calendar appointments; no dates are implied by this document.

## Batch delivery rule

1. Preserve the previously tested **Home + AirVPN independent-tunnel setup**, stored profiles, identities, and safe rollback behavior.
2. Implement the scheduled batch's agreed feature scope, tests, **one combined test APK**, and a **single device checklist**.
3. Review the user's test results and correct regressions **before moving to the next scheduled batch**.
4. Keep the original batch letter in planning, PR summaries, build metadata/release notes, and QA handoffs even if the app is rebranded. A rename changes branding, **not this schedule**.
5. Mark a product batch complete only when its actual feature is implemented and validated. A successful CI build or diagnostic audit by itself is insufficient.

## Important: diagnostic batch-label collision

Some **experimental diagnostic iterations** were also called “Batch C”, “Batch C.1”, “Batch D”, and “Batch E”. Those names are historical identifiers for narrowly scoped tests. They **do not satisfy** the same-letter product schedule entries above.

| Experimental PR | What that iteration actually contains | Product schedule interpretation |
| --- | --- | --- |
| [#26](https://github.com/yooshastan/Wonhee-Proxy/pull/26), “Batch A” | Independent kernel interfaces and multi-tunnel lab | Supports product **A** |
| [#27](https://github.com/yooshastan/Wonhee-Proxy/pull/27), “Batch B” | Reversible priority routing and owned-rule ledger | Supports product **B** |
| [#28](https://github.com/yooshastan/Wonhee-Proxy/pull/28), “Batch C” | **Read-only** protection readiness checks | **Not** product **C** recovery |
| [#29](https://github.com/yooshastan/Wonhee-Proxy/pull/29), “Batch C.1” | Transport marks and app TCP probe | **Not** product **C** recovery |
| [#30](https://github.com/yooshastan/Wonhee-Proxy/pull/30), “Batch D” | **Read-only** endpoint routes and byte counters | **Not** product **D** DNS infrastructure |
| [#31](https://github.com/yooshastan/Wonhee-Proxy/pull/31), “Batch E” | **Read-only** scoped packet observation, DNS status and hypothetical guard | **Not** product **E** tracker blocking |

**Naming rule going forward:** always say **“Product Batch X”** when referring to the roadmap and **“Diagnostics iteration X”** when referencing those historical audit builds. Never infer roadmap progress from a similarly lettered diagnostic APK.

## Where work stands

The next scheduled product feature is **Product Batch C — connection recovery**. The current 0.13.0 diagnostic preview remains read-only: **no actual kill switch, tracker blocking, or DNS enforcement is armed**. Keep that distinction explicit in every public release claim.
