package main

import (
	"os"
	"os/exec"
	"strings"
)

func prepareProgram(templatePath string, commands, functions []string) (string, error) {
	// Read the template file
	templateBytes, err := os.ReadFile(templatePath)
	if err != nil {
		return "", err
	}

	// Substitute the placeholders with the commands
	commandsStr := strings.Join(commands, "\n")
	functionsStr := strings.Join(functions, "\n")
	template := string(templateBytes)
	template = strings.ReplaceAll(template, "{{commands}}", commandsStr)
	template = strings.ReplaceAll(template, "{{functions}}", functionsStr)

	return template, nil
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
