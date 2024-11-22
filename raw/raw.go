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
	SourceUrl []string
}

type RuleSet struct {
	*Raw
	Rules []string
}

var raws = []*Raw{
	{
		Name:     "cn-ips",
		Behavior: "ipcidr",
		SourceUrl: []string{
			"https://raw.githubusercontent.com/ChanthMiao/China-IPv4-List/refs/heads/release/cn.txt",
		},
	},
	{
		Name:     "local-ips",
		Behavior: "ipcidr",
		SourceUrl: []string{
			"https://raw.githubusercontent.com/v2fly/geoip/release/text/private.txt",
		},
	},
	{
		Name:     "cn-max",
		Behavior: "domain",
		SourceUrl: []string{
			"https://raw.githubusercontent.com/v2fly/domain-list-community/refs/heads/release/cn.txt",
			"https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/ChinaMax/ChinaMax_Domain.txt",
		},
	},
	{
		Name:     "ntp",
		Behavior: "domain",
		SourceUrl: []string{
			"https://raw.githubusercontent.com/gamesofts/clash-rules/refs/heads/master/ntp.txt",
		},
	},
}

func LoadRawSources() ([]*RuleSet, error) {
	var result []*RuleSet

	for _, raw := range raws {
		var rules []string

		for _, url := range raw.SourceUrl {
			resp, err := http.Get(url)
			if err != nil {
				return nil, fmt.Errorf("load %s from %s: %s", raw.Name, url, err.Error())
			}

			if resp.StatusCode/100 != 2 {
				return nil, fmt.Errorf("load %s from %s: response %s", raw.Name, url, resp.Status)
			}

			content, err := io.ReadAll(resp.Body)
			if err != nil {
				return nil, fmt.Errorf("load %s from %s: %s", raw.Name, url, err.Error())
			}

			_ = resp.Body.Close()

			for _, line := range strings.Split(string(content), "\n") {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				if strings.HasPrefix(line, "domain:") {
					line = strings.TrimSpace(strings.TrimPrefix(line, "domain:"))
					if line == "" {
						continue
					}
				} else if strings.HasPrefix(line, "ipcidr:") {
					line = strings.TrimSpace(strings.TrimPrefix(line, "ipcidr:"))
					if line == "" {
						continue
					}
				} else if strings.Contains(line, ":") {
					continue
				}
				rules = append(rules, line)
			}
		}

		result = append(result, &RuleSet{
			Raw:   raw,
			Rules: rules,
		})
	}

	return result, nil
}
