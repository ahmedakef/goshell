package main

import "strings"

func WordCompleter(line string, pos int) (head string, completions []string, tail string) {
	head = line[:pos]
	tail = line[pos:]
	if head == "" {
		return
	}

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

	// packageFunctions is a map of package name to a list of functions
	// generated automatically by going to the package page like: https://pkg.go.dev/sync
	// and running the following code in the console:
	// let ulElement = document.getElementById("Documentation_nav_group_Functions");
	// let liElements = ulElement.querySelectorAll("li");
	// let list = [];

	// for(let li of liElements) {
	// 	let aElement = li.querySelector("a");
	// 	if(aElement) {
	// 		list.push(aElement.textContent.trim().split("(")[0]);
	// 	}
	// }
	// console.log(`{"${list.join('", "')}"}`);

	packageFunctions = map[string][]string{
		"fmt":            {"Append", "Appendf", "Appendln", "Errorf", "FormatString", "Fprint", "Fprintf", "Fprintln", "Fscan", "Fscanf", "Fscanln", "Print", "Printf", "Println", "Scan", "Scanf", "Scanln", "Sprint", "Sprintf", "Sprintln", "Sscan", "Sscanf", "Sscanln"},
		"os":             {"Chdir", "Chmod", "Chown", "Chtimes", "Clearenv", "DirFS", "Environ", "Executable", "Exit", "Expand", "ExpandEnv", "Getegid", "Getenv", "Geteuid", "Getgid", "Getgroups", "Getpagesize", "Getpid", "Getppid", "Getuid", "Getwd", "Hostname", "IsExist", "IsNotExist", "IsPathSeparator", "IsPermission", "IsTimeout", "Lchown", "Link", "LookupEnv", "Mkdir", "MkdirAll", "MkdirTemp", "NewSyscallError", "Pipe", "ReadFile", "Readlink", "Remove", "RemoveAll", "Rename", "SameFile", "Setenv", "Symlink", "TempDir", "Truncate", "Unsetenv", "UserCacheDir", "UserConfigDir", "UserHomeDir", "WriteFile"},
		"os/signal":      {"Ignore", "Ignored", "Notify", "NotifyContext", "Reset", "Stop"},
		"path/filepath":  {"Chdir", "Chmod", "Chown", "Chtimes", "Clearenv", "DirFS", "Environ", "Executable", "Exit", "Expand", "ExpandEnv", "Getegid", "Getenv", "Geteuid", "Getgid", "Getgroups", "Getpagesize", "Getpid", "Getppid", "Getuid", "Getwd", "Hostname", "IsExist", "IsNotExist", "IsPathSeparator", "IsPermission", "IsTimeout", "Lchown", "Link", "LookupEnv", "Mkdir", "MkdirAll", "MkdirTemp", "NewSyscallError", "Pipe", "ReadFile", "Readlink", "Remove", "RemoveAll", "Rename", "SameFile", "Setenv", "Symlink", "TempDir", "Truncate", "Unsetenv", "UserCacheDir", "UserConfigDir", "UserHomeDir", "WriteFile"},
		"strings":        {"Clone", "Compare", "Contains", "ContainsAny", "ContainsFunc", "ContainsRune", "Count", "Cut", "CutPrefix", "CutSuffix", "EqualFold", "Fields", "FieldsFunc", "HasPrefix", "HasSuffix", "Index", "IndexAny", "IndexByte", "IndexFunc", "IndexRune", "Join", "LastIndex", "LastIndexAny", "LastIndexByte", "LastIndexFunc", "Map", "Repeat", "Replace", "ReplaceAll", "Split", "SplitAfter", "SplitAfterN", "SplitN", "Title", "ToLower", "ToLowerSpecial", "ToTitle", "ToTitleSpecial", "ToUpper", "ToUpperSpecial", "ToValidUTF8", "Trim", "TrimFunc", "TrimLeft", "TrimLeftFunc", "TrimPrefix", "TrimRight", "TrimRightFunc", "TrimSpace", "TrimSuffix"},
		"syscall":        {"Access", "Acct", "Adjtimex", "AttachLsf", "Bind", "BindToDevice", "BytePtrFromString", "ByteSliceFromString", "Chdir", "Chmod", "Chown", "Chroot", "Clearenv", "Close", "CloseOnExec", "CmsgLen", "CmsgSpace", "Connect", "Creat", "DetachLsf", "Dup", "Dup2", "Dup3", "Environ", "EpollCreate", "EpollCreate1", "EpollCtl", "EpollWait", "Exec", "Exit", "Faccessat", "Fallocate", "Fchdir", "Fchmod", "Fchmodat", "Fchown", "Fchownat", "FcntlFlock", "Fdatasync", "Flock", "ForkExec", "Fstat", "Fstatfs", "Fsync", "Ftruncate", "Futimes", "Futimesat", "Getcwd", "Getdents", "Getegid", "Getenv", "Geteuid", "Getgid", "Getgroups", "Getpagesize", "Getpgid", "Getpgrp", "Getpid", "Getppid", "Getpriority", "Getrlimit", "Getrusage", "GetsockoptInet4Addr", "GetsockoptInt", "Gettid", "Gettimeofday", "Getuid", "Getwd", "Getxattr", "InotifyAddWatch", "InotifyInit", "InotifyInit1", "InotifyRmWatch", "Ioperm", "Iopl", "Kill", "Klogctl", "Lchown", "Link", "Listen", "Listxattr", "LsfSocket", "Lstat", "Madvise", "Mkdir", "Mkdirat", "Mkfifo", "Mknod", "Mknodat", "Mlock", "Mlockall", "Mmap", "Mount", "Mprotect", "Munlock", "Munlockall", "Munmap", "Nanosleep", "NetlinkRIB", "Open", "Openat", "ParseDirent", "ParseUnixRights", "Pause", "Pipe", "Pipe2", "PivotRoot", "Pread", "PtraceAttach", "PtraceCont", "PtraceDetach", "PtraceGetEventMsg", "PtraceGetRegs", "PtracePeekData", "PtracePeekText", "PtracePokeData", "PtracePokeText", "PtraceSetOptions", "PtraceSetRegs", "PtraceSingleStep", "PtraceSyscall", "Pwrite", "Read", "ReadDirent", "Readlink", "Reboot", "Removexattr", "Rename", "Renameat", "Rmdir", "Seek", "Select", "Sendfile", "Sendmsg", "SendmsgN", "Sendto", "SetLsfPromisc", "SetNonblock", "Setdomainname", "Setegid", "Setenv", "Seteuid", "Setfsgid", "Setfsuid", "Setgid", "Setgroups", "Sethostname", "Setpgid", "Setpriority", "Setregid", "Setresgid", "Setresuid", "Setreuid", "Setrlimit", "Setsid", "SetsockoptByte", "SetsockoptICMPv6Filter", "SetsockoptIPMreq", "SetsockoptIPMreqn", "SetsockoptIPv6Mreq", "SetsockoptInet4Addr", "SetsockoptInt", "SetsockoptLinger", "SetsockoptString", "SetsockoptTimeval", "Settimeofday", "Setuid", "Setxattr", "Shutdown", "SlicePtrFromStrings", "Socket", "Socketpair", "Splice", "StartProcess", "Stat", "Statfs", "StringBytePtr", "StringByteSlice", "StringSlicePtr", "Symlink", "Sync", "SyncFileRange", "Sysinfo", "Tee", "Tgkill", "Times", "TimespecToNsec", "TimevalToNsec", "Truncate", "Umask", "Uname", "UnixCredentials", "UnixRights", "Unlink", "Unlinkat", "Unmount", "Unsetenv", "Unshare", "Ustat", "Utime", "Utimes", "UtimesNano", "Wait4", "Write"},
		"bufio":          {"ScanBytes", "ScanLines", "ScanRunes", "ScanWords"},
		"builtin":        {"append", "cap", "clear", "close", "complex", "copy", "delete", "imag", "len", "make", "max", "min", "new", "panic", "print", "println", "real", "recover"},
		"bytes":          {"Clone", "Compare", "Contains", "ContainsAny", "ContainsFunc", "ContainsRune", "Count", "Cut", "CutPrefix", "CutSuffix", "Equal", "EqualFold", "Fields", "FieldsFunc", "HasPrefix", "HasSuffix", "Index", "IndexAny", "IndexByte", "IndexFunc", "IndexRune", "Join", "LastIndex", "LastIndexAny", "LastIndexByte", "LastIndexFunc", "Map", "Repeat", "Replace", "ReplaceAll", "Runes", "Split", "SplitAfter", "SplitAfterN", "SplitN", "Title", "ToLower", "ToLowerSpecial", "ToTitle", "ToTitleSpecial", "ToUpper", "ToUpperSpecial", "ToValidUTF8", "Trim", "TrimFunc", "TrimLeft", "TrimLeftFunc", "TrimPrefix", "TrimRight", "TrimRightFunc", "TrimSpace", "TrimSuffix"},
		"cmp":            {"Compare", "Less", "Or"},
		"container/heap": {"Fix", "Init", "Pop", "Push", "Remove"},
		"context":        {"AfterFunc", "Cause", "WithCancel", "WithCancelCause", "WithDeadline", "WithDeadlineCause", "WithTimeout", "WithTimeoutCause"},
		"log":            {"Fatal", "Fatalf", "Fatalln", "Flags", "Output", "Panic", "Panicf", "Panicln", "Prefix", "Print", "Printf", "Println", "SetFlags", "SetOutput", "SetPrefix", "Writer"},
		"sync":           {"OnceFunc", "OnceValue", "OnceValues"},
	}

	autoComplete = []string{
		// packages
		"fmt",
		"os",
		"os/signal",
		"path/filepath",
		"strings",
		"syscall",
		"bufio",
		"builtin",
		"bytes",
		"cmp",
		"container/heap",
		"context",
		"log",
		"sync",

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
