package raw

import (
    "fmt"
    "io"
    "net/http"
    "sort"
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
            "https://raw.githubusercontent.com/ChanthMiao/China-IPv4-List/release/cn.txt",
            "https://raw.githubusercontent.com/ChanthMiao/China-IPv6-List/release/cn6.txt",
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
            "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/China/China_Domain.txt",
            "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/ChinaMax/ChinaMax_Domain.txt",
        },
    },
    {
        Name:     "ntp",
        Behavior: "domain",
        SourceUrl: []string{
            "https://raw.githubusercontent.com/gamesofts/clash-rules/refs/heads/master/ntp.txt",
        },
    },
    {
        Name:     "ad-max",
        Behavior: "domain",
        SourceUrl: []string{
            "https://raw.githubusercontent.com/gamesofts/clash-rules/refs/heads/master/adguard.txt",
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
                rules = append(rules, line)
            }
        }

        if raw.Behavior == "domain" {
            // 去重，移除已包含父域名的子域名，并去除重复的域名
            rules = deduplicateDomains(rules)

            // 在行的起始拼接字符串
            for i, line := range rules {
                if strings.HasPrefix(line, ".") {
                    rules[i] = "+" + line
                } else {
                    rules[i] = "+." + line
                }
            }

            // 按字母顺序排序
            sort.Strings(rules)
        }

        result = append(result, &RuleSet{
            Raw:   raw,
            Rules: rules,
        })
    }

    return result, nil
}

func deduplicateDomains(domains []string) []string {
    // 首先，移除完全相同的域名
    uniqueDomainsMap := make(map[string]struct{})
    for _, domain := range domains {
        uniqueDomainsMap[domain] = struct{}{}
    }

    // 将唯一域名转换回切片
    uniqueDomains := make([]string, 0, len(uniqueDomainsMap))
    for domain := range uniqueDomainsMap {
        uniqueDomains = append(uniqueDomains, domain)
    }

    // 存储域名及其标签（按.分割）
    domainLabels := make(map[string][]string)
    for _, domain := range uniqueDomains {
        labels := strings.Split(domain, ".")
        domainLabels[domain] = labels
    }

    // 按标签数量（域名层级）排序，层级少的在前
    sort.Slice(uniqueDomains, func(i, j int) bool {
        return len(domainLabels[uniqueDomains[i]]) < len(domainLabels[uniqueDomains[j]])
    })

    included := make(map[string]struct{})
    var result []string

    for _, domain := range uniqueDomains {
        labels := domainLabels[domain]
        foundParent := false
        for i := 1; i < len(labels); i++ {
            parent := strings.Join(labels[i:], ".")
            if _, ok := included[parent]; ok {
                foundParent = true
                break
            }
        }
        if !foundParent {
            included[domain] = struct{}{}
            result = append(result, domain)
        }
    }

    return result
}
