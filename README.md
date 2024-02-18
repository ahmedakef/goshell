# Goshell

Goshell is REPL shell for golang.

## Table of Contents

1. [Installation](#installation)
2. [Usage](#usage)
3. [Contributing](#contributing)
4. [Tests](#tests)
5. [License](#license)

## Installation

```sh
$ go install github.com/ahmedakef/goshell@latest
```
## Features

- auto import the needed libraries using `goimports` just write `fmt.Print` and `fmt will be imported.
- autocompletion for languages keywords and libraries's functions.
- print the variablles by writing them, no need to use `fmt.Print()`

## Contributing

If you want to accept contributions to your project, provide instructions on how to do so.

## Examples

## live  demo
TODO

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
a:=1
b:=2
a
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
func use(vals ...interface{}) {
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
func add(x,y int) int {
    return x+y
}
a:=1
b:=2
add(a,b)
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
func use(vals ...interface{}) {
	for _, val := range vals {
		_ = val
	}
}
```

</td>
</tr>
<tr><td>6 lines</td><td>21 lines</td></tr></tbody></table>


## Contact

ahmedakef - aemed.akef.1@gmail.com
