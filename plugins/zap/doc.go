// Package zap wraps OWASP ZAP dynamic scanning (DAST) as a BANNIN
// plugin satisfying pkg/plugin.Scanner. Unlike the static-analysis
// plugins, its scan target is a running web application's http(s) URL,
// not a directory — Run rejects non-URL targets up front. Like the
// other plugins, it depends only on pkg/plugin and the standard
// library; registration is cmd/bannin's job.
package zap
