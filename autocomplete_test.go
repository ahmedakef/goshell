package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWordCompleter(t *testing.T) {
	tests := []struct {
		name        string
		line        string
		pos         int
		head        string
		completions []string
		tail        string
	}{
		{
			name:        "Package known, function specified",
			line:        "fmt.Pr",
			pos:         6,
			head:        "fmt.",
			completions: []string{"Print", "Printf", "Println"},
			tail:        "",
		},
		{
			name:        "Empty line",
			line:        "",
			pos:         0,
			head:        "",
			completions: autoComplete,
			tail:        "",
		},
		{
			name:        "Package not known",
			line:        "foo.",
			pos:         4,
			head:        "foo.",
			completions: []string{},
			tail:        "",
		},
		{
			name:        "Package known, no function specified",
			line:        "fmt.",
			pos:         4,
			head:        "fmt.",
			completions: packageFunctions["fmt"],
			tail:        "",
		},
		{
			name:        "Package known, function specified",
			line:        "fmt.Pr",
			pos:         6,
			head:        "fmt.",
			completions: []string{"Print", "Printf", "Println"},
			tail:        "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			head, completions, tail := WordCompleter(tt.line, tt.pos)
			assert.Equal(t, tt.head, head)
			assert.ElementsMatch(t, tt.completions, completions)
			assert.Equal(t, tt.tail, tail)
		})
	}
}
