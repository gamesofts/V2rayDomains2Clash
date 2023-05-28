package main

import (
	"fmt"
	"os"
	"path"
	"github.com/kr328/domains2providers/raw"
	"github.com/kr328/domains2providers/rule"
)

func main() {
	if len(os.Args) < 3 {
		println("Usage: <v2ray-domains-path> <output-path>")

		os.Exit(1)
	}

	data := path.Join(os.Args[1], "data")
	generated := os.Args[2]

	_ = os.MkdirAll(generated, 0755)

	ruleSets, err := rule.ParseDirectory(data)
	if err != nil {
		println("Load domains: " + err.Error())

		os.Exit(1)
	}

	//ad
	adMap := make(map[string]int)


	for name := range ruleSets {
		tags, err := rule.Resolve(ruleSets, name)
		if err != nil {
			println("Resolve " + name + ": " + err.Error())

			continue
		}

		for tag, rules := range tags {
			var outputPath string

			if tag == "" {
				outputPath = path.Join(generated, fmt.Sprintf("%s.yaml", name))
			} else {
				outputPath = path.Join(generated, fmt.Sprintf("%s@%s.yaml", name, tag))
			}

			

			file, err := os.OpenFile(outputPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
			if err != nil {
				println("Write file " + outputPath + ": " + err.Error())

				continue
			}

			_, _ = file.WriteString(fmt.Sprintf("payload:\n"))

			
			for _, domain := range rules {
				_, _ = file.WriteString(fmt.Sprintf("  - \"%s\"\n", domain))
				if tag == "ads" {
					adMap[domain] = 1
				}
				if name == "category-ads-all" {
					adMap[domain] = 1
				}
			}
			_ = file.Close()
		}
	}

	raws, err := raw.LoadRawSources()
	if err != nil {
		println("Load raw resources: " + err.Error())

		os.Exit(1)
	}

	for _, r := range raws {
		outputPath := path.Join(generated, r.Name+".yaml")

		file, err := os.OpenFile(outputPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err != nil {
			println("Write file " + outputPath + ": " + err.Error())

			continue
		}

		_, _ = file.WriteString(fmt.Sprintf("payload:\n"))

		for _, domain := range r.Rules {
			_, _ = file.WriteString(fmt.Sprintf("  - \"%s\"\n", domain))
		}

		_ = file.Close()
	}

	//ad
	var adPath = path.Join(generated, fmt.Sprintf("ads.yaml"))
	adFile, adErr := os.OpenFile(adPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if adErr != nil {
		println("Write file " + adPath + ": " + adErr.Error())
	}
	_, _ = adFile.WriteString(fmt.Sprintf("payload:\n"))
	for domain := range adMap {
		_, _ = adFile.WriteString(fmt.Sprintf("  - \"%s\"\n", domain))
	}
	_ = adFile.Close()
}
