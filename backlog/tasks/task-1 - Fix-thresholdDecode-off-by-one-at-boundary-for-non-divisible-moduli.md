---
id: TASK-1
title: Fix thresholdDecode off-by-one at boundary for non-divisible moduli
status: To Do
assignee: []
created_date: '2026-02-18 21:50'
labels:
  - audit
  - correctness
dependencies: []
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Audit finding 1 (Nethermind AuditAgent scan 36): For q=65521 where q%4!=0, threshold=floor(q/4)=16380 and 3*threshold=49140. The check `lt(diff, mul(3, threshold))` excludes diff=49140, but this value lies inside the mathematical band (q/4, 3q/4) since 49140 < 49140.75. Fix: use `lt(diff, add(mul(3, threshold), 1))` or document that the band is [threshold+1, 3*threshold-1] (exclusive on both ends).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Fix thresholdDecode to include diff=3*threshold when q%4!=0
- [ ] #2 Add test for boundary value diff=3*threshold with q=65521
- [ ] #3 Update docstring to match implementation precisely
<!-- AC:END -->
