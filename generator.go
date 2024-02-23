package main

import (
	"bytes"
	"fmt"
	"os"
	"text/template"

	"golang.org/x/tools/imports"
)

func prepareProgram(templatePath string, commands []command, functions []function) (string, error) {
	// Read the template file
	t := template.Must(template.New("template.txt").Parse(programTemplate))
	var buf bytes.Buffer
	err := t.Execute(&buf, map[string]any{
		"commands":  commands,
		"functions": functions,
	})
	if err != nil {
		return "", err
	}

	return buf.String(), nil
}

func formatProgram(programPath string) error {

	output, err := imports.Process(programPath, nil, nil)
	if err != nil {
		fmt.Println("Error formatting the program:", err)
		return err
	}
	err = os.WriteFile(programPath, output, 0644)
	if err != nil {
		fmt.Println("Error writing the formatted program:", err)
		return err
	}

	return nil
}
