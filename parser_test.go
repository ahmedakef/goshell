package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name             string
		input            string
		expectedAssigned []string
		expectedDeclared []string
		expectedError    error
	}{
		{
			name:  "simple expression1",
			input: "1 + 2",
		},
		{
			name:  "simple print",
			input: "fmt.Println(\"Hello, World!\")",
		},
		{
			name:             "assignment",
			input:            "a:= 1",
			expectedAssigned: []string{"a"},
		},
		{
			name:             "assignment without colon",
			input:            "a = 1",
			expectedAssigned: []string{"a"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			av, err := ParseStatement(tt.input)
			if tt.expectedError != nil {
				assert.Equal(t, tt.expectedError, err)
				return
			}
			assert.NoError(t, err)

			assert.Equal(t, tt.expectedAssigned, av.VariablesAssigned)
			assert.Equal(t, tt.expectedDeclared, av.VariablesDeclared)
		})
	}
}

func TestParseFunction(t *testing.T) {
	tests := []struct {
		name           string
		input          string
		expectedName   string
		expectedReturn []string
		expectedError  error
	}{
		{
			name:           "valid expression",
			input:          "func add(a int, b int) int { return a+b }",
			expectedName:   "add",
			expectedReturn: []string{"int"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseFunction(tt.input)
			if tt.expectedError != nil {
				assert.Equal(t, tt.expectedError, err)
				return
			}
			assert.NoError(t, err)

			assert.Equal(t, tt.expectedName, result.Name)
			assert.Equal(t, tt.expectedReturn, result.returnVariables)
		})
	}
}
