package zap

import "strings"

// zapOutput mirrors ZAP's traditional JSON report (the -quickout /
// zap-baseline shape), trimmed to the fields this plugin uses. Numeric
// values arrive as JSON strings ("riskcode":"2"), matching the report
// format.
type zapOutput struct {
	Site []zapSite `json:"site"`
}

type zapSite struct {
	Name   string     `json:"@name"`
	Alerts []zapAlert `json:"alerts"`
}

type zapAlert struct {
	PluginID  string        `json:"pluginid"`
	Alert     string        `json:"alert"`
	RiskCode  string        `json:"riskcode"`
	RiskDesc  string        `json:"riskdesc"`
	Desc      string        `json:"desc"`
	Solution  string        `json:"solution"`
	Reference string        `json:"reference"`
	CWEID     string        `json:"cweid"`
	Instances []zapInstance `json:"instances"`
}

type zapInstance struct {
	URI    string `json:"uri"`
	Method string `json:"method"`
}

// stripTags flattens the light HTML markup ZAP embeds in desc/solution
// fields ("<p>…</p>") into plain text for the Finding model. It is not
// a sanitizer — renderers escape everything anyway — just readability.
func stripTags(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	inTag := false
	for _, r := range s {
		switch {
		case r == '<':
			inTag = true
			b.WriteRune(' ')
		case r == '>':
			inTag = false
		case !inTag:
			b.WriteRune(r)
		}
	}
	return strings.Join(strings.Fields(b.String()), " ")
}

// urlsFrom extracts http(s) URLs from a tag-stripped ZAP reference
// field, which is a run of URLs wrapped in paragraph tags.
func urlsFrom(htmlText string) []string {
	var urls []string
	for _, tok := range strings.Fields(stripTags(htmlText)) {
		if strings.HasPrefix(tok, "http://") || strings.HasPrefix(tok, "https://") {
			urls = append(urls, tok)
		}
	}
	return urls
}
