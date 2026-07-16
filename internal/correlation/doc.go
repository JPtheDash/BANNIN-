// Package correlation links related findings across scanners to reduce
// duplicate signal. Today that means exact-duplicate removal (Dedupe);
// reconciling the same advisory published under different identifiers
// (CVE vs GHSA vs GO-...) is planned, deeper correlation work.
package correlation
