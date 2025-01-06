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
        Name:     "cncidr",
        Behavior: "ipcidr",
        SourceUrl: []string{
            "https://raw.githubusercontent.com/ChanthMiao/China-IPv4-List/release/cn.txt",
            "https://raw.githubusercontent.com/ChanthMiao/China-IPv6-List/release/cn6.txt",
        },
    },
    {
        Name:     "lancidr",
        Behavior: "ipcidr",
        SourceUrl: []string{
            "https://raw.githubusercontent.com/v2fly/geoip/release/text/private.txt",
        },
    },
    {
        Name:     "direct",
        Behavior: "domain",
        SourceUrl: []string{
            "https://raw.githubusercontent.com/v2fly/domain-list-community/release/cn.txt",
            "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/ChinaMax/ChinaMax_Domain.txt",
            "https://raw.githubusercontent.com/gamesofts/clash-rules/master/my-cn.txt",
        },
    },
    {
        Name:     "proxy",
        Behavior: "domain",
        SourceUrl: []string{
            "https://raw.githubusercontent.com/v2fly/domain-list-community/release/geolocation-!cn.txt",
            "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Global/Global_Domain.txt",
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
        Name:     "adv",
        Behavior: "domain",
        SourceUrl: []string{
            "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/Filters/AWAvenue-Ads-Rule-hosts.txt",
            "https://raw.githubusercontent.com/gamesofts/clash-rules/master/my-ad.txt",
        },
    },
    {
        Name:     "media",
        Behavior: "domain",
        SourceUrl: []string{
            "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/GlobalMedia/GlobalMedia_Domain.txt",
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
            resp.Body.Close()
            if err != nil {
                return nil, fmt.Errorf("load %s from %s: %s", raw.Name, url, err.Error())
            }

            lines := strings.Split(string(content), "\n")
            for _, line := range lines {
                line = strings.TrimSpace(line)
                if line == "" || strings.HasPrefix(line, "#") {
                    continue
                }
                rules = append(rules, line)
            }
        }

        // Process rules based on behavior
        var processedRules []string
        switch raw.Behavior {
        case "domain":
            processedRules = processDomainRules(rules)
        case "ipcidr":
            processedRules = rules // No additional processing needed
        default:
            processedRules = rules
        }

        result = append(result, &RuleSet{
            Raw:   raw,
            Rules: processedRules,
        })
    }

    return result, nil
}

func processDomainRules(rules []string) []string {
    domainSet := make(map[string]struct{})
    for _, line := range rules {
        domain := processDomainLine(line)
        if domain == "" {
            continue
        }
        domainSet[domain] = struct{}{}
    }

    // Convert set to slice
    uniqueDomains := make([]string, 0, len(domainSet))
    for domain := range domainSet {
        uniqueDomains = append(uniqueDomains, domain)
    }

    // Deduplicate domains by removing subdomains included in parent domains
    deduplicatedDomains := deduplicateDomains(uniqueDomains)

    // Prefix '+.'
    for i, domain := range deduplicatedDomains {
        deduplicatedDomains[i] = "+." + domain
    }

    // Sort
    sort.Strings(deduplicatedDomains)

    return deduplicatedDomains
}

func processDomainLine(line string) string {
    line = strings.TrimSpace(line)
    if line == "" || strings.HasPrefix(line, "#") {
        return ""
    }
    if line == "" || strings.HasPrefix(line, "!") {
        return ""
    }
    if strings.HasPrefix(line, "regexp:") {
        return ""
    }
    if strings.Contains(line, "localhost") {
        return ""
    }
    // Remove prefixes like "domain:" and "full:"
    for _, prefix := range []string{"domain:", "full:", "127.0.0.1"} {
        if strings.HasPrefix(line, prefix) {
            line = strings.TrimPrefix(line, prefix)
            break
        }
    }
    // Remove suffixes starting with ':@'
    if idx := strings.Index(line, ":@"); idx != -1 {
        line = line[:idx]
    }
    line = strings.TrimSpace(line)
    // if line starts with '.', remove it
    if strings.HasPrefix(line, ".") {
        line = strings.TrimPrefix(line, ".")
    }
    return line
}

func deduplicateDomains(domains []string) []string {
    // First, remove exact duplicates
    domainSet := make(map[string]struct{})
    for _, domain := range domains {
        domainSet[domain] = struct{}{}
    }

    // Convert set to slice
    uniqueDomains := make([]string, 0, len(domainSet))
    for domain := range domainSet {
        uniqueDomains = append(uniqueDomains, domain)
    }

    // Sort domains by label count (fewest labels first)
    sort.Slice(uniqueDomains, func(i, j int) bool {
        return len(strings.Split(uniqueDomains[i], ".")) < len(strings.Split(uniqueDomains[j], "."))
    })

    // Deduplicate subdomains
    result := []string{}
    for _, domain := range uniqueDomains {
        include := true
        for _, existing := range result {
            if domain == existing || strings.HasSuffix(domain, "."+existing) {
                include = false
                break
            }
        }
        if include {
            result = append(result, domain)
        }
    }
    return result
}
