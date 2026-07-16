package correlation

import (
	"sort"
	"strings"

	"github.com/jyotidash/bannin/pkg/plugin"
)

// ReconcileAliases merges findings that describe the same advisory
// published under different identifier schemes — OSV's GHSA-/PYSEC-/GO-
// ids versus Trivy's CVEs, or one database mirroring another. Vulnerability
// databases cross-reference these through alias lists, which plugins
// surface as Finding.Aliases.
//
// Two findings merge only when they affect the same package version at
// the same location AND their identifier sets (RuleID plus Aliases)
// overlap, directly or transitively. Findings without package metadata
// (SAST, secrets, IaC) pass through untouched: alias reconciliation is
// meaningful only for advisory-style findings, and anything looser
// would risk collapsing genuinely distinct issues.
//
// The merged finding keeps the fields of the most severe member (ties
// go to input order) — when scanners disagree about how bad an advisory
// is, underreporting is the wrong direction to err. All other
// identifiers become its Aliases, references and CWEs are unioned, and
// Metadata records which other scanners agreed via "also_reported_by".
// Input order is otherwise preserved.
func ReconcileAliases(findings []plugin.Finding) []plugin.Finding {
	type groupKey struct{ path, pkg, version string }
	groups := make(map[groupKey][]int)
	for i, f := range findings {
		pkg, version := f.Metadata["package"], f.Metadata["version"]
		if pkg == "" || version == "" {
			continue
		}
		k := groupKey{f.Location.Path, pkg, version}
		groups[k] = append(groups[k], i)
	}

	// Each cluster of alias-linked findings collapses into one merged
	// finding, placed at the cluster's earliest index.
	replacement := make(map[int]plugin.Finding)
	drop := make(map[int]bool)
	for _, idxs := range groups {
		for _, cluster := range clusterByIdentifier(findings, idxs) {
			if len(cluster) < 2 {
				continue
			}
			replacement[cluster[0]] = merge(findings, cluster)
			for _, i := range cluster[1:] {
				drop[i] = true
			}
		}
	}
	if len(replacement) == 0 {
		return findings
	}

	out := findings[:0]
	for i := range findings {
		if drop[i] {
			continue
		}
		if m, ok := replacement[i]; ok {
			out = append(out, m)
			continue
		}
		out = append(out, findings[i])
	}
	return out
}

// clusterByIdentifier partitions idxs (ascending) into clusters whose
// identifier sets overlap transitively, via union-find. Each returned
// cluster preserves ascending index order.
func clusterByIdentifier(findings []plugin.Finding, idxs []int) [][]int {
	parent := make(map[int]int, len(idxs))
	for _, i := range idxs {
		parent[i] = i
	}
	var find func(int) int
	find = func(x int) int {
		if parent[x] != x {
			parent[x] = find(parent[x])
		}
		return parent[x]
	}

	owner := make(map[string]int) // identifier -> first index claiming it
	for _, i := range idxs {
		for _, id := range identifiers(findings[i]) {
			if j, ok := owner[id]; ok {
				parent[find(i)] = find(j)
			} else {
				owner[id] = i
			}
		}
	}

	byRoot := make(map[int][]int)
	for _, i := range idxs {
		r := find(i)
		byRoot[r] = append(byRoot[r], i)
	}
	clusters := make([][]int, 0, len(byRoot))
	for _, c := range byRoot {
		clusters = append(clusters, c)
	}
	return clusters
}

// identifiers returns a finding's advisory ids (RuleID plus Aliases),
// uppercased so schemes compare case-insensitively.
func identifiers(f plugin.Finding) []string {
	ids := make([]string, 0, 1+len(f.Aliases))
	if f.RuleID != "" {
		ids = append(ids, strings.ToUpper(f.RuleID))
	}
	for _, a := range f.Aliases {
		if a != "" {
			ids = append(ids, strings.ToUpper(a))
		}
	}
	return ids
}

// merge collapses a cluster into one finding based on its most severe
// member (ties broken by input order, cluster being index-ascending).
func merge(findings []plugin.Finding, cluster []int) plugin.Finding {
	base := cluster[0]
	for _, i := range cluster[1:] {
		if findings[i].Severity.Rank() > findings[base].Severity.Rank() {
			base = i
		}
	}
	out := findings[base]

	// Every identifier across the cluster except the surviving RuleID
	// becomes an alias, first-seen spelling kept, sorted for determinism.
	seen := map[string]bool{strings.ToUpper(out.RuleID): true}
	var aliases []string
	for _, i := range cluster {
		f := findings[i]
		for _, id := range append([]string{f.RuleID}, f.Aliases...) {
			key := strings.ToUpper(id)
			if id == "" || seen[key] {
				continue
			}
			seen[key] = true
			aliases = append(aliases, id)
		}
	}
	sort.Strings(aliases)
	out.Aliases = aliases

	out.References = unionOrdered(base, cluster, findings, func(f plugin.Finding) []string { return f.References })
	out.CWE = unionOrdered(base, cluster, findings, func(f plugin.Finding) []string { return f.CWE })

	var others []string
	seenScanner := map[string]bool{out.Scanner: true}
	for _, i := range cluster {
		if s := findings[i].Scanner; !seenScanner[s] {
			seenScanner[s] = true
			others = append(others, s)
		}
	}
	if len(others) > 0 {
		sort.Strings(others)
		// Copy before writing: out.Metadata still aliases the base
		// finding's map.
		meta := make(map[string]string, len(out.Metadata)+1)
		for k, v := range out.Metadata {
			meta[k] = v
		}
		meta["also_reported_by"] = strings.Join(others, ", ")
		out.Metadata = meta
	}
	return out
}

// unionOrdered unions get(f) across the cluster, base's values first,
// the rest in cluster order, duplicates removed.
func unionOrdered(base int, cluster []int, findings []plugin.Finding, get func(plugin.Finding) []string) []string {
	seen := make(map[string]bool)
	var out []string
	add := func(vals []string) {
		for _, v := range vals {
			if v == "" || seen[v] {
				continue
			}
			seen[v] = true
			out = append(out, v)
		}
	}
	add(get(findings[base]))
	for _, i := range cluster {
		if i != base {
			add(get(findings[i]))
		}
	}
	return out
}
