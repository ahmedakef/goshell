# Goshell

Goshell is REPL shell for golang.

the project is inspired by [rango](https://github.com/emicklei/rango/) but took different decisions.

## Table of Contents

- [Installation](#installation)
- [Features](#features)
- [Examples](#examples)
- [Requirements](#requirements)
- [Contact](#contact)

## Installation

```sh
go install github.com/ahmedakef/goshell@latest
```
## Features

- auto import the needed libraries using `goimports` just write `fmt.Print()` and `fmt` will be imported.
- autocompletion for languages keywords and libraries's functions and types without the need for language server.
- print the variablles by writing them, no need to use `fmt.Print()`
- supports all shell line editing commands supported by [liner](https://github.com/peterh/liner?tab=readme-ov-file#line-editing)

## Examples

## live  demo
![Example Demo](docs/example.gif?raw=true "Example demo")

### Simple variable printing


<table>
<thead>
<tr>
<th><strong>code you write</strong></th>
<th><strong>generated code</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>

```go
>>> a:=1
>>> b:=2
>>> a
1
```

</td>
<td>

```go
package main

import "fmt"

func main() {
	a := 1
	b := 2
	fmt.Println(a)
	use(a, b)
}

// used to avoid "declared and not used" error
func use(vals ...any) {
	for _, val := range vals {
		_ = val
	}
}
```

</td>
</tr>
<tr><td>3 lines</td><td>17 lines</td></tr></tbody></table>


### Calling functions


<table>
<thead>
<tr>
<th><strong>code you write</strong></th>
<th><strong>generated code</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>

```go
>>> func add(x,y int) int {
...     return x+y
... }
>>> a:=1
>>> b:=2
>>> add(a,b)
3
```

</td>
<td>

```go
package main

import "fmt"

func add(x, y int) int {
	return x + y
}

func main() {
	a := 1
	b := 2
	fmt.Println(add(a, b))
	use(a, b)
}

// used to avoid "declared and not used" error
func use(vals ...any) {
	for _, val := range vals {
		_ = val
	}
}
```

</td>
</tr>
<tr><td>6 lines</td><td>21 lines</td></tr></tbody></table>

## Requirements
`goimports` should be installed in the system.

## Contact

ahmedakef - aemed.akef.1@gmail.com
