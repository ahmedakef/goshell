package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/gocolly/colly"
	"golang.org/x/exp/maps"
)

const (
	version                = "0.0.1"
	listURI                = "https://pkg.go.dev/std/"
	packagesFunctionsFiles = "pkgFunctions.json"
	packagesNamesFiles     = "pkgNames.json"
	listPageSelector       = "article.go-Main-article table tbody tr td:first-child div div:first-child a"
)

var mapOfLibs = map[string][]string{}

func main() {
	listPageCollector := colly.NewCollector()
	listPageCollector.SetRequestTimeout(120 * time.Second)

	listPageCollector.OnRequest(func(r *colly.Request) {
		fmt.Println("Visiting", r.URL)
	})
	listPageCollector.OnHTML(listPageSelector, detailsPagerVisiter)
	err := listPageCollector.Visit(listURI)
	if err != nil {
		fmt.Println(err)
	}

	jsonData, err := json.Marshal(mapOfLibs)
	if err != nil {
		fmt.Println(err)
	}
	os.WriteFile(packagesFunctionsFiles, jsonData, 0644)
	commands := [][]string{
		{"sed", "-i", "", "s/\\[\\]/{}/g", packagesFunctionsFiles},
		{"sed", "-i", "", "s/\\[/{/g", packagesFunctionsFiles},
		{"sed", "-i", "", "s/\\]/}/g", packagesFunctionsFiles},
		{"sed", "-i", "", "s/},/},\\n/g", packagesFunctionsFiles},
	}
	executeCommands(commands)

	packgesNames := maps.Keys(mapOfLibs)
	jsonData, err = json.Marshal(packgesNames)
	if err != nil {
		fmt.Println(err)
	}
	os.WriteFile(packagesNamesFiles, jsonData, 0644)
	commands = [][]string{
		{"sed", "-i", "", "s/\",\"/\",\\n\"/g", packagesNamesFiles},
	}
	executeCommands(commands)

}

func executeCommands(commands [][]string) {
	for _, command := range commands {
		cmd := exec.Command(command[0], command[1:]...)
		fmt.Println("Running command", cmd.String())
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		err := cmd.Run()
		if err != nil {
			fmt.Println("Stderr:", stderr.String())
			fmt.Println(err)
		}
	}
}
