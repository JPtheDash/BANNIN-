// Package server will expose BANNIN's orchestration and scan-history data
// over HTTP for the dashboard (Milestone 17) and any future integrations
// (Jira, DefectDojo — Phase 5). It is an adapter in the hexagonal sense:
// it depends on internal/storage and internal/scanner through their
// interfaces, never the reverse.
package server
