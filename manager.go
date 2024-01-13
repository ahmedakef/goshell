package main

import (
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"strings"
)

const (
	_programPath  = "program.go"
	_templatePath = "template.txt"
)

type Manager struct {
	commands            []string
	functions           []string
	variables           []string
	lastCommandFunction bool
	programPath         string
	templatePath        string
}

func newManager() *Manager {
	return &Manager{
		commands:     []string{},
		functions:    []string{},
		programPath:  _programPath,
		templatePath: _templatePath,
	}
}

func (m *Manager) addInput(input string) {
	if isFunctionDeclaration(input) {
		m.addFunction(input)
		return
	}
	m.addCommand(input)
}

func (m *Manager) addCommand(command string) {
	command, newVariables := processCommand(command)
	m.variables = append(m.variables, newVariables...)
	m.commands = append(m.commands, command)

	m.lastCommandFunction = false
}
func (m *Manager) addFunction(function string) {
	m.functions = append(m.functions, function)
	m.lastCommandFunction = true
}

func (m *Manager) removeLastInput() {
	if m.lastCommandFunction {
		m.functions = m.functions[:len(m.functions)-1]
	} else {
		m.commands = m.commands[:len(m.commands)-1]
	}
}

func (m *Manager) runProgram() error {
	commands := m.commands
	lastElementIndex := len(m.commands) - 1
	if isExperimentalInput(m.commands[lastElementIndex]) {
		commands = append(m.commands[:lastElementIndex], commandPrintted(m.commands[lastElementIndex]))
	}
	commands = append(commands, m.useCall())
	program, err := prepareProgram(m.templatePath, commands, m.functions)
	if err != nil {
		fmt.Println("Error:", err)
	}

	// Save the substituted template to the output file
	err = os.WriteFile(m.programPath, []byte(program), fs.FileMode(0644))
	if err != nil {
		return err
	}

	err = formatProgram(m.programPath)
	if err != nil {
		return err
	}

	cmd := exec.Command("go", "run", m.programPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Println(string(output))
		return err
	}
	if len(output) > 0 {
		fmt.Print(string(output))
	}
	return nil
}

func (m *Manager) getProgram() string {
	commands := append(m.commands, m.useCall())
	program, err := prepareProgram(m.templatePath, commands, m.functions)
	if err != nil {
		fmt.Println("Error:", err)
	}
	return program
}

func (m *Manager) useCall() string {
	return fmt.Sprintf("use(%s)", strings.Join(m.variables, ", "))
}

func commandPrintted(command string) string {
	return fmt.Sprintf("fmt.Println(%s)", command)
}

func isFunctionDeclaration(command string) bool {
	return strings.HasPrefix(command, "func")
}

func isExperimentalInput(command string) bool {
	containsColon := strings.Contains(command, ":=")
	if containsColon || isFunctionDeclaration(command) {
		return false
	}
	return true
}

func (m *Manager) cleanUp() {
	os.Remove(m.programPath)
}
