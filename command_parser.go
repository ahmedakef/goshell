package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
)

// ParseStatement is a modified version of go/parser.ParseExpr
func ParseStatement(x string) (*AstVisitor, error) {
	// parse x within the context of a complete package for correct scopes;
	// put x alone on a separate line (handles line comments), followed by a ';'
	// to force an error if the expression is incomplete

	var node ast.Node
	code := "package p;func _(){" + x + "\n;}"
	file, err := parser.ParseFile(token.NewFileSet(), "", code, 0)
	if err != nil {
		return nil, err
	}
	node = file.Decls[0].(*ast.FuncDecl).Body.List[0]

	av := new(AstVisitor)
	ast.Walk(av, node)
	return av, nil
}

// AstVisitor implements a ast.Visitor and collect variable and import info
type AstVisitor struct {
	VariablesAssigned []string
	VariablesDeclared []string
	Imports           []string
	Functions         []string
	IsExpression      bool
}

// Visit inspects the type of a Node to detect a Assignment, Declaration or Import
func (av *AstVisitor) Visit(node ast.Node) ast.Visitor {
	switch node := node.(type) {
	case *ast.AssignStmt:
		for _, each := range node.Lhs {
			av.VariablesAssigned = append(av.VariablesAssigned, each.(*ast.Ident).Name)
		}
	case *ast.DeclStmt:
		for _, each := range node.Decl.(*ast.GenDecl).Specs {
			valueSpec, ok := each.(*ast.ValueSpec)
			if ok {
				for _, other := range valueSpec.Names {
					av.VariablesDeclared = append(av.VariablesDeclared, other.Name)
				}
			}
		}
	case *ast.ImportSpec:
		av.Imports = append(av.Imports, node.Path.Value)
	case *ast.ExprStmt:
		av.IsExpression = true
	}
	return av
}

func isFunctionDeclaration(statement string) bool {
	return strings.HasPrefix(statement, "func")
}

func isExperimentalInput(av *AstVisitor) bool {
	return av.IsExpression
}
