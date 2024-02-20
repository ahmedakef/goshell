package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"log"

	"github.com/gocolly/colly"
)

const (
	detailURIBase       = "https://pkg.go.dev/"
	detailsPageSelector = "li.DocNav-functions ul li a"
)

func listPageHandler(el *colly.HTMLElement) {
	libPartOfURI := el.ChildAttr("td:first-child div div:first-child a", "href")
	if libPartOfURI == "" {
		// nested inside a directory
		libPartOfURI = el.ChildAttr("td:first-child div span:first-child a", "href")
		if libPartOfURI == "" {
			// the directory itself
			return
		}
	}
	elID := el.ChildAttr("td:first-child", "data-id")
	if elID == "" {
		elID = el.Attr("data-id")
		if elID == "" {
			log.Println("No data-id found")
			return
		}
	}
	packagename := strings.Join(strings.Split(elID, "-"), "/")

	functionsNames := visitPackage(detailURIBase + libPartOfURI)

	mapOfLibs[packagename] = functionsNames
}

func visitPackage(libURI string) []string {
	functionsNames := []string{}
	detailsPageCollector := colly.NewCollector()
	detailsPageCollector.SetRequestTimeout(120 * time.Second)
	detailsPageCollector.OnRequest(func(r *colly.Request) {
		log.Println("Visiting", r.URL)
	})
	detailsPageCollector.OnHTML(detailsPageSelector, func(e *colly.HTMLElement) {
		functionText := strings.TrimSpace(e.Text)
		function := strings.Split(functionText, "(")[0]
		functionsNames = append(functionsNames, function)
	})

	detailsPageCollector.OnResponse(func(r *colly.Response) {
		if !*debugFlag {
			return
		}
		err := os.WriteFile("detailsResponse.html", r.Body, 0644)
		if err != nil {
			fmt.Println(err)
		}
	})

	err := detailsPageCollector.Visit(libURI)
	if err != nil {
		log.Println(err)
	}

	return functionsNames
}
