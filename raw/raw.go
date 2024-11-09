package raw

import (
	"fmt"
	"io"
	"net/http"
	"strings"
)

type Raw struct {
	Name      string
	Behavior  string
	SourceUrl string
}

type RuleSet struct {
	*Raw
	Rules []string
}

var raws = []*Raw{
	{
		Name:      "cn-ips",
		Behavior:  "ipcidr",
		SourceUrl: "https://raw.githubusercontent.com/v2fly/geoip/release/text/cn.txt",
	},
	{
		Name:      "local-ips",
		Behavior:  "ipcidr",
		SourceUrl: "https://raw.githubusercontent.com/v2fly/geoip/release/text/private.txt",
	},
	{
		Name:      "ntp",
		Behavior:  "domain",
		SourceUrl: "https://raw.githubusercontent.com/gamesofts/clash-rules/refs/heads/master/ntp.txt",
	},
}

func LoadRawSources() ([]*RuleSet, error) {
	var result []*RuleSet

	for _, raw := range raws {
		resp, err := http.Get(raw.SourceUrl)
		if err != nil {
			return nil, fmt.Errorf("load %s: %s", raw.Name, err.Error())
		}

		if resp.StatusCode/100 != 2 {
			return nil, fmt.Errorf("load %s: response %s", raw.Name, resp.Status)
		}

		content, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("load %s: %s", raw.Name, err.Error())
		}

		var rules []string

		for _, line := range strings.Split(string(content), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			if strings.Contains(line, ":") {
				continue
			}
			rules = append(rules, line)
		}

		_ = resp.Body.Close()

		result = append(result, &RuleSet{
			Raw:   raw,
			Rules: rules,
		})
	}

	return result, nil
}
