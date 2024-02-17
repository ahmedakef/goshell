package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
)

func ParseFunction(x string) (function, error) {
	function := function{
		Src: x,
	}
	code := "package p;" + x
	file, err := parser.ParseFile(token.NewFileSet(), "", code, 0)
	if err != nil {
		return function, err
	}
	funcDecl := file.Decls[0].(*ast.FuncDecl)
	function.Name = funcDecl.Name.Name
	returnVariables := funcDecl.Type.Results
	if returnVariables == nil {
		return function, nil
	}
	for _, variable := range returnVariables.List {
		ident, ok := variable.Type.(*ast.Ident)
		if ok {
			function.returnVariables = append(function.returnVariables, ident.Name)
		}
	}
	return function, nil
}

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
	callExpression    bool   // this is a call to function or method expression
	calleeName        string // name of the function or method being called
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
		callExpr, ok := node.X.(*ast.CallExpr)
		if ok {
			ident, ok := callExpr.Fun.(*ast.Ident)
			if ok {
				av.callExpression = true
				av.calleeName = ident.Name
			}
		}
	case *ast.IncDecStmt: // like a++ or a--
	}
	return av
}

func isFunctionDeclaration(statement string) bool {
	return strings.HasPrefix(statement, "func")
}
