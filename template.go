package main

var programTemplate = `
package main
{{range .functions}}
    {{.Src}}
{{end}}
func main() {
	{{- range .commands}}
        {{- if not .Hidden}}
            {{.Src -}}
        {{end -}}
    {{end}}
}

// used to avoid "declared and not used" error
func use(vals ...any) {
    for _, val := range vals {
        _ = val
    }
}`
