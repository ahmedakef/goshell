package main

import (
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"strings"
)

const (
	_templatePath = "template.txt"
)

type command struct {
	Src               string
	variablesAssigned []string
	variablesDeclared []string
	isExpression      bool
	Hidden            bool
}
type Manager struct {
	commands             []command
	functions            []string
	lastInputFunctionDef bool
	programPath          string
	templatePath         string
}

func newManager(programPath string) *Manager {
	return &Manager{
		commands:     []command{},
		functions:    []string{},
		programPath:  programPath,
		templatePath: _templatePath,
	}
}

func (m *Manager) addInput(input string) error {
	if isFunctionDeclaration(input) {
		m.addFunction(input)
		m.lastInputFunctionDef = true
		return nil
	}
	av, err := ParseStatement(input)
	if err != nil {
		return err
	}
	m.addCommand(input, av)
	m.lastInputFunctionDef = false
	return nil
}

func (m *Manager) addCommand(src string, av *AstVisitor) {
	m.commands = append(m.commands, command{
		Src:               src,
		variablesAssigned: av.VariablesAssigned,
		variablesDeclared: av.VariablesDeclared,
		isExpression:      av.IsExpression,
	})
}
func (m *Manager) addFunction(function string) {
	m.functions = append(m.functions, function)
}

func (m *Manager) removeLastInput() {
	if m.lastInputFunctionDef {
		m.functions = m.functions[:len(m.functions)-1]
	} else {
		m.commands = m.commands[:len(m.commands)-1]
	}
}

func (m *Manager) runProgram() (string, error) {
	commands := m.prepareCommands()
	program, err := prepareProgram(m.templatePath, commands, m.functions)
	if err != nil {
		return "", err
	}

	// Save the substituted template to the output file
	err = os.WriteFile(m.programPath, []byte(program), fs.FileMode(0644))
	if err != nil {
		return "", err
	}

	err = formatProgram(m.programPath)
	if err != nil {
		return "", err
	}

	cmd := exec.Command("go", "run", m.programPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Println(string(output))
		return "", err
	}
	return string(output), nil
}

func (m *Manager) getProgram() (string, error) {
	commands := m.prepareCommands()
	return prepareProgram(m.templatePath, commands, m.functions)
}

func (m *Manager) prepareCommands() []command {
	commands := make([]command, len(m.commands))
	copy(commands, m.commands)

	for i := range commands {
		if !commands[i].isExpression {
			continue
		}
		if i < len(commands)-1 || m.lastInputFunctionDef {
			commands[i].Hidden = true
			continue
		}
		if strings.HasPrefix(commands[i].Src, "fmt.Print") {
			continue
		}
		commands[i].Src = commandPrintted(commands[i].Src)
	}
	commands = append(commands, m.useCallStatement())
	return commands
}

func (m *Manager) extractVariables() []string {
	variables := []string{}
	for _, command := range m.commands {
		variables = append(variables, command.variablesDeclared...)
		variables = append(variables, command.variablesAssigned...)
	}
	return variables
}

func (m *Manager) useCallStatement() command {
	variables := m.extractVariables()
	if len(variables) == 0 {
		return command{}
	}
	return command{
		Src:          fmt.Sprintf("use(%s)", strings.Join(variables, ", ")),
		isExpression: true,
	}
}

func commandPrintted(command string) string {
	return fmt.Sprintf("fmt.Println(%s)", command)
}

func (m *Manager) cleanUp() {
	os.Remove(m.programPath)
}
