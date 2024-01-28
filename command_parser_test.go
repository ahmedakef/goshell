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
		{
			name:  "function declaration",
			input: "func add(a int, b int) int { return a + b }",
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
	assert.False(t, true)
}
