package main

import (
	"bytes"
	"html/template"
	"os/exec"
)

func prepareProgram(templatePath string, commands []command, functions []string) (string, error) {
	// Read the template file

	t := template.Must(template.New("template.txt").ParseFiles(templatePath))
	var buf bytes.Buffer
	err := t.Execute(&buf, map[string]interface{}{
		"commands":  commands,
		"functions": functions,
	})
	if err != nil {
		return "", err
	}

	return buf.String(), nil
}

func formatProgram(programPath string) error {
	cmd := exec.Command("go", "fmt", programPath)
	err := cmd.Run()
	if err != nil {
		return err
	}

	cmd = exec.Command("goimports", "-w", programPath)
	err = cmd.Run()
	if err != nil {
		return err
	}

	return nil
}
