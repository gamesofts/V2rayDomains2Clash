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
		SourceUrl: "https://raw.githubusercontent.com/17mon/china_ip_list/master/china_ip_list.txt",
	},
	{
		Name:      "local-ips",
		Behavior:  "ipcidr",
		SourceUrl: "https://raw.githubusercontent.com/v2fly/geoip/release/text/private.txt",
	},
	{
		Name:      "public-dns",
		Behavior:  "ipcidr",
		SourceUrl: "https://gist.githubusercontent.com/Kr328/83120bec98f8596676e916fa3be969c8/raw/public-dns.txt",
	},
	{
		Name:      "public-dns-domain",
		Behavior:  "domain",
		SourceUrl: "https://gist.githubusercontent.com/Kr328/38b9d7907d0e3e9ee1a9bacd99dfa6f4/raw/public-dns-domain.txt",
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
