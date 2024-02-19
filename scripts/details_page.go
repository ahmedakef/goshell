package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/gocolly/colly"
)

const (
	detailURIBase       = "https://pkg.go.dev/"
	detailsPageSelector = "li.DocNav-functions ul li a"
)

func detailsPagerVisiter(el *colly.HTMLElement) {
	packagename := el.Text
	functionsNames := []string{}
	libURI := detailURIBase + el.Attr("href")
	detailsPageCollector := colly.NewCollector()
	detailsPageCollector.SetRequestTimeout(120 * time.Second)
	detailsPageCollector.OnRequest(func(r *colly.Request) {
		fmt.Println("Visiting", r.URL)
	})
	detailsPageCollector.OnHTML(detailsPageSelector, func(e *colly.HTMLElement) {
		functionText := strings.TrimSpace(e.Text)
		function := strings.Split(functionText, "(")[0]
		functionsNames = append(functionsNames, function)

	})

	err := detailsPageCollector.Visit(libURI)
	if err != nil {
		fmt.Println(err)
	}

	mapOfLibs[packagename] = functionsNames
}
