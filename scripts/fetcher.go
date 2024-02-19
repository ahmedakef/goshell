package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/gocolly/colly"
	"golang.org/x/exp/maps"
)

const (
	version                = "0.0.1"
	listURI                = "https://pkg.go.dev/std/"
	detailURIBase          = "https://pkg.go.dev/"
	packagesFunctionsFiles = "pkgFunctions.go"
	packagesNamesFiles     = "pkgNames.json"
)

func main() {
	listPageCollector := colly.NewCollector()
	listPageCollector.SetRequestTimeout(120 * time.Second)
	mapOfLibs := map[string][]string{}

	listPageCollector.OnRequest(func(r *colly.Request) {
		fmt.Println("Visiting", r.URL)
	})
	listPageCollector.OnHTML("article.go-Main-article table tbody tr td:first-child div div:first-child a", func(el *colly.HTMLElement) {
		packagename := el.Text
		functionsNames := []string{}
		libURI := detailURIBase + el.Attr("href")
		detailsPageCollector := colly.NewCollector()
		detailsPageCollector.SetRequestTimeout(120 * time.Second)
		detailsPageCollector.OnRequest(func(r *colly.Request) {
			fmt.Println("Visiting", r.URL)
		})
		detailsPageCollector.OnHTML("li.DocNav-functions ul li a", func(e *colly.HTMLElement) {
			functionText := strings.TrimSpace(e.Text)
			function := strings.Split(functionText, "(")[0]
			functionsNames = append(functionsNames, function)

		})

		err := detailsPageCollector.Visit(libURI)
		if err != nil {
			fmt.Println(err)
		}

		mapOfLibs[packagename] = functionsNames
	})
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
