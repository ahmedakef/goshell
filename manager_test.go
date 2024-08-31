package main

import (
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestManager_RunProgram(t *testing.T) {
	tests := []struct {
		name           string
		input          []string
		expectedOutput string
		expectedError  error
	}{
		{
			name: "simple addition",
			input: []string{
				"1+1",
			},
			expectedOutput: "2\n",
			expectedError:  nil,
		},
		{
			name: "function declaration and call",
			input: []string{
				"func add(a int, b int) int { return a+b }",
				"add(2,3)",
			},
			expectedOutput: "5\n",
			expectedError:  nil,
		},
		{
			name: "declation then experiment",
			input: []string{
				"a:=1",
				"a",
				"a=3",
				"a",
			},
			expectedOutput: "3\n",
			expectedError:  nil,
		},
		{
			name: "slice initialization",
			input: []string{
				"a:= []int{1}",
				"a",
			},
			expectedOutput: "[]int{1}\n",
			expectedError:  nil,
		},
		{
			name: "assignment, experiment, function declaration",
			input: []string{
				"a:=1",
				"a",
				"func add(a int, b int) int { return a+b }",
			},
			expectedOutput: "",
			expectedError:  nil,
		},
		{
			name: "function declaration without return variables and call",
			input: []string{
				"func x() { fmt.Println(3) }",
				"x()",
			},
			expectedOutput: "3\n",
			expectedError:  nil,
		},
		{
			name: "slice indexin",
			input: []string{
				"a:= []int{1}",
				"a[0] = 2",
				"a[0]",
			},
			expectedOutput: "2\n",
			expectedError:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a temporary directory for the program file
			tempDir, err := os.MkdirTemp("", "test-program")
			if err != nil {
				t.Fatal("Failed to create temporary directory:", err)
			}
			defer os.RemoveAll(tempDir)

			// Create a Manager instance
			m := newManager(path.Join(tempDir, "program.go"))

			for _, input := range tt.input {
				m.addInput(input)
			}
			output, err := m.runProgram()
			assert.Equal(t, tt.expectedError, err)
			assert.Equal(t, tt.expectedOutput, output)

		})
	}
}
