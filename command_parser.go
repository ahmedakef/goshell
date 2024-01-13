package main

import (
	"strings"
)

func processCommand(command string) (string, []string) {
	if !containsNewDeclarations(command) {
		return command, nil
	}
	// new variables are declared but not used
	// call use on them to avoid "declared and not used" error

	newVariables := getNewVariables(command)
	return command, newVariables
}

func containsNewDeclarations(command string) bool {
	return strings.Contains(command, ":=")
}

func getNewVariables(command string) []string {
	variableSection := strings.Split(command, ":=")[0]
	variables := strings.Split(variableSection, ",")
	return variables
}
