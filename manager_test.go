package main

import (
	"os"
	"testing"
)

func TestManager_RunProgram(t *testing.T) {
	tests := []struct {
		name           string
		input          []string
		expectedOutput string
		expectedError  error
	}{
		{
			name:           "Test case 1",
			input:          []string{"fmt.Println(\"Hello, World!\")"},
			expectedOutput: "Hello, World!\n",
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
			m := newManager()

			for _, input := range tt.input {
				m.addInput(input)
			}
			err = m.runProgram()
			if err != tt.expectedError {
				t.Fatalf("Expected error: %v, but got: %v", tt.expectedError, err)
			}

		})
	}
}
