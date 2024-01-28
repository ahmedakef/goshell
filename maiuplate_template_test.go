package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPrepareProgram(t *testing.T) {
	// Test case 1: Valid template path, commands, and functions
	templatePath := "template.txt"
	commands := []command{
		{Src: "a:=1"},
	}
	functions := []string{"func add(a int, b int) int { return a + b }"}

	expectedResult := "expected result"

	result, err := prepareProgram(templatePath, commands, functions)

	assert.Equal(t, nil, err)
	assert.Equal(t, expectedResult, result)

}
