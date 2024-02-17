package main

import "strings"

func WordCompleter(line string, pos int) (head string, completions []string, tail string) {
	head = line[:pos]
	tail = line[pos:]

	headSplitted := strings.SplitN(head, ".", 2)
	packageName := headSplitted[0]

	if !contains(supportedPackages, packageName) {
		// this is a not known package, we match to the language keywords
		completions = getPossipleSuggestions(autoComplete, packageName)
		if len(completions) > 0 {
			head = ""
		}
		return
	}

	head = packageName + "."
	function := ""
	if len(headSplitted) == 2 {
		function = headSplitted[1]
	}

	allPkgFunctions := packageFunctions[packageName]
	if function == "" {
		completions = allPkgFunctions
		return
	}

	completions = getPossipleSuggestions(allPkgFunctions, function)
	return
}

func getPossipleSuggestions(possibleWords []string, word string) []string {
	var completions []string
	for _, possibleWord := range possibleWords {
		if strings.HasPrefix(strings.ToLower(possibleWord), strings.ToLower(word)) {
			completions = append(completions, possibleWord)
		}
	}
	return completions
}

func contains(arr []string, str string) bool {
	for _, a := range arr {
		if a == str {
			return true
		}
	}
	return false
}

var (
	supportedPackages = []string{"fmt", "os", "os/signal", "path/filepath", "strings", "syscall"}
	packageFunctions  = map[string][]string{
		"fmt":           {"Println", "Printf", "Print", "Sprint", "Sprintf", "Sprintln", "Errorf", "Fprint", "Fprintf", "Fprintln", "Scan", "Scanf", "Scanln", "Sscan", "Sscanf", "Sscanln", "Fscan", "Fscanf", "Fscanln", "Error", "New", "Errorf", "Fprintf", "Fprintln", "Fscan", "Fscanf", "Fscanln"},
		"os":            {"Create", "NewFile", "Open", "OpenFile", "Remove", "RemoveAll", "Rename", "Stat", "Lstat", "Chmod", "Chown", "Chtimes", "Mkdir", "MkdirAll", "Readlink", "Symlink", "Link", "Truncate", "ReadFile", "WriteFile", "TempDir", "TempFile", "Getwd", "Chdir", "Chroot", "Mkdir", "MkdirAll", "Remove", "RemoveAll", "Rename", "Stat", "Lstat", "Chmod", "Chown", "Chtimes", "Readlink", "Symlink", "Link", "Truncate", "ReadFile", "WriteFile", "TempDir", "TempFile", "Getwd", "Chdir", "Chroot"},
		"os/signal":     {"Notify", "Stop"},
		"path/filepath": {"Base", "Clean", "Dir", "EvalSymlinks", "Ext", "FromSlash", "Glob", "IsAbs", "Join", "Match", "Rel", "Split", "ToSlash", "VolumeName", "Walk", "WalkDir", "Base", "Clean", "Dir", "EvalSymlinks", "Ext", "FromSlash", "Glob", "IsAbs", "Join", "Match", "Rel", "Split", "ToSlash", "VolumeName", "Walk", "WalkDir"},
		"strings":       {"Contains", "Count", "HasPrefix", "HasSuffix", "Index", "Join", "LastIndex", "Repeat", "Replace", "Split", "ToLower", "ToUpper", "Trim", "TrimLeft", "TrimRight", "TrimSpace", "TrimPrefix", "TrimSuffix", "Fields", "NewReader", "NewReplacer", "Contains", "Count", "HasPrefix", "HasSuffix", "Index", "Join", "LastIndex", "Repeat", "Replace", "Split", "ToLower", "ToUpper", "Trim", "TrimLeft", "TrimRight", "TrimSpace", "TrimPrefix", "TrimSuffix", "Fields", "NewReader", "NewReplacer"},
		"syscall":       {"Chdir", "Chmod", "Chown", "Close", "Dup", "Dup2", "Exit", "Fchdir", "Fchmod", "Fchown", "ForkExec", "Getegid", "Geteuid", "Getgid", "Getgroups", "Getpgid", "Getpgrp", "Getpid", "Getppid", "Getuid", "Kill", "Link", "Lchown", "Mkdir", "Mkdirat", "Mkfifo", "Mknod", "Open", "Openat", "Pipe", "Read", "Readlink", "Rename", "Rmdir", "Setegid", "Seteuid", "Setgid", "Setpgid", "Setpriority", "Setregid", "Setresgid", "Setresuid", "Setreuid", "Setuid", "Symlink", "Sync", "Syscall", "Truncate", "Umask", "Uname", "Unlink", "Unlinkat", "Utimes", "UtimesNano", "Wait4", "Write", "Chdir", "Chmod", "Chown", "Close", "Dup", "Dup2", "Exit", "Fchdir", "Fchmod", "Fchown", "ForkExec", "Getegid", "Geteuid", "Getgid", "Getgroups", "Getpgid", "Getpgrp", "Getpid", "Getppid", "Getuid", "Kill", "Link", "Lchown", "Mkdir", "Mkdirat", "Mkfifo", "Mknod", "Open", "Openat", "Pipe", "Read", "Readlink", "Rename", "Rmdir", "Setegid", "Seteuid", "Setgid", "Setpgid", "Setpriority", "Setregid", "Setresgid", "Setresuid", "Setreuid", "Setuid", "Symlink", "Sync", "Syscall", "Truncate", "Umask", "Uname", "Unlink", "Unlinkat", "Utimes", "UtimesNano", "Wait4", "Write"},
	}

	autoComplete = []string{
		// packages
		"fmt",
		"os",
		"os/signal",
		"path/filepath",
		"strings",
		"syscall",

		// language keywords
		"package",
		"import",
		"func",
		"var",
		"const",
		"return",
		"if",
		"else",
		"for",
		"range",
		"switch",
		"case",
		"default",
		"select",
		"break",
		"continue",
		"goto",
		"fallthrough",
		"defer",
		"go",
		"chan",
		"map",
		"struct",
		"interface",
		"type",
		"append",
		"cap",
		"close",
		"complex",
		"copy",
		"delete",
		"imag",
		"len",
		"make",
		"new",
		"panic",
		"real",
		"bool",
		"byte",
		"complex64",
		"complex128",
		"error",
		"float32",
		"float64",
		"int",
		"int8",
		"int16",
		"int32",
		"int64",
		"rune",
		"string",

		// used for goshell
		".quit",
		".vars",
		".source",
		".undo",
		".help",
	}
)
