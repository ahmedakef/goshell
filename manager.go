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
	variables           map[string]struct{}
	lastCommandFunction bool
	programPath         string
	templatePath        string
}

func newManager() *Manager {
	return &Manager{
		commands:     []string{},
		functions:    []string{},
		variables:    make(map[string]struct{}),
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
	for _, variable := range newVariables {
		m.variables[variable] = struct{}{}
	}
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
		lastElementIndex := len(m.commands) - 1
		deleteVariables := getNewVariables(m.commands[lastElementIndex])
		for _, variable := range deleteVariables {
			delete(m.variables, variable)
		}
		m.commands = m.commands[:lastElementIndex]
	}
}

func (m *Manager) runProgram() error {
	commands := make([]string, len(m.commands)+1)
	lastElementIndex := len(m.commands) - 1
	copy(commands, m.commands) // copy to avoid modifying the original slice
	if isExperimentalInput(m.commands[lastElementIndex]) {
		commands[lastElementIndex] = commandPrintted(m.commands[lastElementIndex])
		m.commands = m.commands[:lastElementIndex]
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

func (m *Manager) getVariables() []string {
	variables := make([]string, 0, len(m.variables))
	for variable := range m.variables {
		variables = append(variables, variable)
	}
	return variables
}

func (m *Manager) useCall() string {
	return fmt.Sprintf("use(%s)", strings.Join(m.getVariables(), ", "))
}

func commandPrintted(command string) string {
	return fmt.Sprintf("fmt.Println(%s)", command)
}

func (m *Manager) cleanUp() {
	os.Remove(m.programPath)
}
