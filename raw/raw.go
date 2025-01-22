package raw

import (
    "fmt"
    "io"
    "net/http"
    "sort"
    "strings"
)

// Raw 表示原始规则信息
type Raw struct {
    Name         string
    Behavior     string
    SourceUrl    []string   // 来源URL列表
    BlacklistUrl []string   // 黑名单URL列表（仅 Behavior=domain 时生效）
}

// RuleSet 表示最终处理后的规则集
type RuleSet struct {
    *Raw
    Rules []string
}

// 这里给出一个初始的 raws，可以按需添加 BlacklistUrl
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
        BlacklistUrl: []string{
            "https://raw.githubusercontent.com/v2fly/domain-list-community/release/geolocation-!cn.txt",
            "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Global/Global_Domain.txt",
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

// LoadRawSources 读取 raws 中所有内容并做必要处理，返回最终的多个 RuleSet
func LoadRawSources() ([]*RuleSet, error) {
    var result []*RuleSet

    for _, raw := range raws {
        // 1. 读取 SourceUrl 内容
        sourceLines, err := loadLinesFromURLs(raw.Name, raw.SourceUrl)
        if err != nil {
            return nil, err
        }
        
        // 2. 如果 Behavior = domain，额外读取 BlacklistUrl 内容
        var blacklistLines []string
        if raw.Behavior == "domain" && len(raw.BlacklistUrl) > 0 {
            blacklistLines, err = loadLinesFromURLs(raw.Name, raw.BlacklistUrl)
            if err != nil {
                return nil, err
            }
        }

        // 3. 根据不同 Behavior 做处理
        var processedRules []string
        switch raw.Behavior {
        case "domain":
            // 3.1 先处理 SourceUrl 得到域名规则
            processedRules = processDomainRules(sourceLines)

            // 3.2 如果有 BlacklistUrl，则处理黑名单域名
            if len(blacklistLines) > 0 {
                blacklistedDomains := processDomainRules(blacklistLines)
                processedRules = filterBlacklistedDomains(processedRules, blacklistedDomains)
            }

        case "ipcidr":
            // 这里示例不做其他特殊处理，直接使用原始 lines
            processedRules = sourceLines

        default:
            processedRules = sourceLines
        }

        // 4. 生成 RuleSet
        rs := &RuleSet{
            Raw:   raw,
            Rules: processedRules,
        }
        result = append(result, rs)
    }

    return result, nil
}

// loadLinesFromURLs 读取多个 URL 的文本内容，按行合并返回（会跳过空行与 # 注释）
func loadLinesFromURLs(ruleName string, urls []string) ([]string, error) {
    var lines []string
    for _, url := range urls {
        resp, err := http.Get(url)
        if err != nil {
            return nil, fmt.Errorf("load %s from %s: %v", ruleName, url, err)
        }
        if resp.StatusCode/100 != 2 {
            return nil, fmt.Errorf("load %s from %s: response %s", ruleName, url, resp.Status)
        }

        content, err := io.ReadAll(resp.Body)
        _ = resp.Body.Close()
        if err != nil {
            return nil, fmt.Errorf("load %s from %s: %v", ruleName, url, err)
        }

        for _, line := range strings.Split(string(content), "\n") {
            line = strings.TrimSpace(line)
            if line == "" || strings.HasPrefix(line, "#") {
                continue
            }
            lines = append(lines, line)
        }
    }
    return lines, nil
}

// processDomainRules 对域名类规则进行处理（去空、去注释、去前后缀等），并做去重和去子域名操作
func processDomainRules(rules []string) []string {
    domainSet := make(map[string]struct{})
    for _, line := range rules {
        domain := processDomainLine(line)
        if domain == "" {
            continue
        }
        domainSet[domain] = struct{}{}
    }

    // 将 set 转换为切片
    uniqueDomains := make([]string, 0, len(domainSet))
    for domain := range domainSet {
        uniqueDomains = append(uniqueDomains, domain)
    }

    // 去除子域名重复，比如 "qq.com" 会覆盖 "www.qq.com"
    deduplicatedDomains := deduplicateDomains(uniqueDomains)

    // 在每个域名前面加 "+."
    for i, domain := range deduplicatedDomains {
        deduplicatedDomains[i] = "+." + domain
    }

    // 排序
    sort.Strings(deduplicatedDomains)

    return deduplicatedDomains
}

// processDomainLine 处理单行域名规则，主要是去掉常见前缀/后缀、跳过特例等
func processDomainLine(line string) string {
    line = strings.TrimSpace(line)
    if (line == "") {
        return ""
    }
    
    // 常见不处理的行
    for _, igonre := range []string{ "#", "!", "regexp:", "localhost", "payload:"} {
        if strings.Contains(line, igonre) {
            return ""
        }
    }

    // 去除常见的 "domain:"、"full:"、"127.0.0.1" 等前缀
    for _, prefix := range []string{"domain:", "full:", "127.0.0.1", "  - \"+."} {
        if strings.HasPrefix(line, prefix) {
            line = strings.TrimPrefix(line, prefix)
            break
        }
    }

    // 去除形如 "abc.com:@xxx" 的后缀信息
    for _, suffix := range []string{":@", "\""} {
         if idx := strings.Index(line, suffix); idx != -1 {
            line = line[:idx]
            break
        }
    }
    
    line = strings.TrimSpace(line)
    // 如果开头是 '.' 则去掉
    if strings.HasPrefix(line, ".") {
        line = strings.TrimPrefix(line, ".")
    }
    return line
}

// deduplicateDomains 将域名做去重，同时自动剔除子域名：若已经包含 "qq.com"，则 "www.qq.com" 不再保留
func deduplicateDomains(domains []string) []string {
    // 1. 去重
    domainSet := make(map[string]struct{})
    for _, d := range domains {
        domainSet[d] = struct{}{}
    }
    uniqueDomains := make([]string, 0, len(domainSet))
    for d := range domainSet {
        uniqueDomains = append(uniqueDomains, d)
    }

    // 2. 按 “点” 的数量排序，从少到多
    sort.Slice(uniqueDomains, func(i, j int) bool {
        return len(strings.Split(uniqueDomains[i], ".")) < len(strings.Split(uniqueDomains[j], "."))
    })

    // 3. 剔除子域名
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

// filterBlacklistedDomains 将被黑名单包含的域名过滤掉。
// 如果黑名单包含 "abc.com"，则其子域名 "www.abc.com" 也要被剔除。
func filterBlacklistedDomains(domains, blacklisted []string) []string {
    // 由于传入的 blacklisted 可能已经带有 "+." 前缀，所以先处理一下去掉 "+."
    cleanBlacklist := make([]string, 0, len(blacklisted))
    for _, d := range blacklisted {
        d = strings.TrimPrefix(d, "+.")
        cleanBlacklist = append(cleanBlacklist, d)
    }

    var filtered []string
    for _, domain := range domains {
        // 域名本身去掉 "+." 再与黑名单匹配
        cleanDomain := strings.TrimPrefix(domain, "+.")

        exclude := false
        for _, b := range cleanBlacklist {
            if cleanDomain == b || strings.HasSuffix(cleanDomain, "."+b) {
                exclude = true
                break
            }
        }
        if !exclude {
            filtered = append(filtered, domain)
        }
    }
    return filtered
}
