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
	detailsPageSelector = "li.DocNav-functions,li.DocNav-types"
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
	membersNames := []string{}
	// for some reason the "li.DocNav-types > ul > li > ul > li > a" selector return an item twice
	membrersLookup := map[string]struct{}{}
	detailsPageCollector := colly.NewCollector()
	detailsPageCollector.SetRequestTimeout(120 * time.Second)
	detailsPageCollector.OnRequest(func(r *colly.Request) {
		log.Println("Visiting", r.URL)
	})
	detailsPageCollector.OnHTML(detailsPageSelector, func(category *colly.HTMLElement) {
		category.ForEach("ul > li", func(i int, e *colly.HTMLElement) {
			if category.Attr("class") == "DocNav-functions" {
				functionText := strings.TrimSpace(e.ChildText("a:first-child"))
				function := clearFunctionName(functionText)
				membersNames = append(membersNames, function)
			} else if category.Attr("class") == "DocNav-types" {
				e.ForEach("li.DocNav-types > ul > li > a", func(i int, el *colly.HTMLElement) {
					text := strings.TrimSpace(el.Text)
					if strings.Contains(text, "type") {
						typeCleared := strings.Split(text, "type ")[1]
						if _, ok := membrersLookup[typeCleared]; !ok {
							membersNames = append(membersNames, typeCleared)
							membrersLookup[typeCleared] = struct{}{}
						}
					}
				})
				e.ForEach("li.DocNav-types > ul > li > ul > li > a", func(i int, el *colly.HTMLElement) {
					text := strings.TrimSpace(el.Text)
					if strings.HasPrefix(text, "(") {
						// type methods, skipped for now as it is complex to support them
						return
					}
					function := clearFunctionName(text)
					if _, ok := membrersLookup[function]; !ok {
						membersNames = append(membersNames, function)
						membrersLookup[function] = struct{}{}
					}

				})
			}
		})
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

	return membersNames
}

func clearFunctionName(function string) string {
	return strings.Split(function, "(")[0]
}
