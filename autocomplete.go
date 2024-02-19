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
		"bufio":    {"ScanBytes", "ScanLines", "ScanRunes", "ScanWords"},
		"builtin":  {"append", "cap", "clear", "close", "complex", "copy", "delete", "imag", "len", "make", "max", "min", "new", "panic", "print", "println", "real", "recover"},
		"bytes":    {"Clone", "Compare", "Contains", "ContainsAny", "ContainsFunc", "ContainsRune", "Count", "Cut", "CutPrefix", "CutSuffix", "Equal", "EqualFold", "Fields", "FieldsFunc", "HasPrefix", "HasSuffix", "Index", "IndexAny", "IndexByte", "IndexFunc", "IndexRune", "Join", "LastIndex", "LastIndexAny", "LastIndexByte", "LastIndexFunc", "Map", "Repeat", "Replace", "ReplaceAll", "Runes", "Split", "SplitAfter", "SplitAfterN", "SplitN", "Title", "ToLower", "ToLowerSpecial", "ToTitle", "ToTitleSpecial", "ToUpper", "ToUpperSpecial", "ToValidUTF8", "Trim", "TrimFunc", "TrimLeft", "TrimLeftFunc", "TrimPrefix", "TrimRight", "TrimRightFunc", "TrimSpace", "TrimSuffix"},
		"cmp":      {"Compare", "Less", "Or"},
		"context":  {"AfterFunc", "Cause", "WithCancel", "WithCancelCause", "WithDeadline", "WithDeadlineCause", "WithTimeout", "WithTimeoutCause"},
		"crypto":   {"RegisterHash"},
		"embed":    {},
		"encoding": {},
		"errors":   {"As", "Is", "Join", "New", "Unwrap"},
		"expvar":   {"Do", "Handler", "Publish"},
		"flag":     {"Arg", "Args", "Bool", "BoolFunc", "BoolVar", "Duration", "DurationVar", "Float64", "Float64Var", "Func", "Int", "Int64", "Int64Var", "IntVar", "NArg", "NFlag", "Parse", "Parsed", "PrintDefaults", "Set", "String", "StringVar", "TextVar", "Uint", "Uint64", "Uint64Var", "UintVar", "UnquoteUsage", "Var", "Visit", "VisitAll"},
		"fmt":      {"Append", "Appendf", "Appendln", "Errorf", "FormatString", "Fprint", "Fprintf", "Fprintln", "Fscan", "Fscanf", "Fscanln", "Print", "Printf", "Println", "Scan", "Scanf", "Scanln", "Sprint", "Sprintf", "Sprintln", "Sscan", "Sscanf", "Sscanln"},
		"hash":     {},
		"html":     {"EscapeString", "UnescapeString"},
		"image":    {"RegisterFormat"},
		"io":       {"Copy", "CopyBuffer", "CopyN", "Pipe", "ReadAll", "ReadAtLeast", "ReadFull", "WriteString"},
		"log":      {"Fatal", "Fatalf", "Fatalln", "Flags", "Output", "Panic", "Panicf", "Panicln", "Prefix", "Print", "Printf", "Println", "SetFlags", "SetOutput", "SetPrefix", "Writer"},
		"maps":     {"Clone", "Copy", "DeleteFunc", "Equal", "EqualFunc"},
		"math":     {"Abs", "Acos", "Acosh", "Asin", "Asinh", "Atan", "Atan2", "Atanh", "Cbrt", "Ceil", "Copysign", "Cos", "Cosh", "Dim", "Erf", "Erfc", "Erfcinv", "Erfinv", "Exp", "Exp2", "Expm1", "FMA", "Float32bits", "Float32frombits", "Float64bits", "Float64frombits", "Floor", "Frexp", "Gamma", "Hypot", "Ilogb", "Inf", "IsInf", "IsNaN", "J0", "J1", "Jn", "Ldexp", "Lgamma", "Log", "Log10", "Log1p", "Log2", "Logb", "Max", "Min", "Mod", "Modf", "NaN", "Nextafter", "Nextafter32", "Pow", "Pow10", "Remainder", "Round", "RoundToEven", "Signbit", "Sin", "Sincos", "Sinh", "Sqrt", "Tan", "Tanh", "Trunc", "Y0", "Y1", "Yn"},
		"mime":     {"AddExtensionType", "ExtensionsByType", "FormatMediaType", "ParseMediaType", "TypeByExtension"},
		"net":      {"JoinHostPort", "LookupAddr", "LookupCNAME", "LookupHost", "LookupPort", "LookupTXT", "ParseCIDR", "Pipe", "SplitHostPort"},
		"os":       {"Chdir", "Chmod", "Chown", "Chtimes", "Clearenv", "DirFS", "Environ", "Executable", "Exit", "Expand", "ExpandEnv", "Getegid", "Getenv", "Geteuid", "Getgid", "Getgroups", "Getpagesize", "Getpid", "Getppid", "Getuid", "Getwd", "Hostname", "IsExist", "IsNotExist", "IsPathSeparator", "IsPermission", "IsTimeout", "Lchown", "Link", "LookupEnv", "Mkdir", "MkdirAll", "MkdirTemp", "NewSyscallError", "Pipe", "ReadFile", "Readlink", "Remove", "RemoveAll", "Rename", "SameFile", "Setenv", "Symlink", "TempDir", "Truncate", "Unsetenv", "UserCacheDir", "UserConfigDir", "UserHomeDir", "WriteFile"},
		"path":     {"Base", "Clean", "Dir", "Ext", "IsAbs", "Join", "Match", "Split"},
		"plugin":   {},
		"reflect":  {"Copy", "DeepEqual", "Swapper"},
		"regexp":   {"Match", "MatchReader", "MatchString", "QuoteMeta"},
		"runtime":  {"BlockProfile", "Breakpoint", "CPUProfile", "Caller", "Callers", "GC", "GOMAXPROCS", "GOROOT", "Goexit", "GoroutineProfile", "Gosched", "KeepAlive", "LockOSThread", "MemProfile", "MutexProfile", "NumCPU", "NumCgoCall", "NumGoroutine", "ReadMemStats", "ReadTrace", "SetBlockProfileRate", "SetCPUProfileRate", "SetCgoTraceback", "SetFinalizer", "SetMutexProfileFraction", "Stack", "StartTrace", "StopTrace", "ThreadCreateProfile", "UnlockOSThread", "Version"},
		"slices":   {"BinarySearch", "BinarySearchFunc", "Clip", "Clone", "Compact", "CompactFunc", "Compare", "CompareFunc", "Concat", "Contains", "ContainsFunc", "Delete", "DeleteFunc", "Equal", "EqualFunc", "Grow", "Index", "IndexFunc", "Insert", "IsSorted", "IsSortedFunc", "Max", "MaxFunc", "Min", "MinFunc", "Replace", "Reverse", "Sort", "SortFunc", "SortStableFunc"},
		"sort":     {"Find", "Float64s", "Float64sAreSorted", "Ints", "IntsAreSorted", "IsSorted", "Search", "SearchFloat64s", "SearchInts", "SearchStrings", "Slice", "SliceIsSorted", "SliceStable", "Sort", "Stable", "Strings", "StringsAreSorted"},
		"strconv":  {"AppendBool", "AppendFloat", "AppendInt", "AppendQuote", "AppendQuoteRune", "AppendQuoteRuneToASCII", "AppendQuoteRuneToGraphic", "AppendQuoteToASCII", "AppendQuoteToGraphic", "AppendUint", "Atoi", "CanBackquote", "FormatBool", "FormatComplex", "FormatFloat", "FormatInt", "FormatUint", "IsGraphic", "IsPrint", "Itoa", "ParseBool", "ParseComplex", "ParseFloat", "ParseInt", "ParseUint", "Quote", "QuoteRune", "QuoteRuneToASCII", "QuoteRuneToGraphic", "QuoteToASCII", "QuoteToGraphic", "QuotedPrefix", "Unquote", "UnquoteChar"},
		"strings":  {"Clone", "Compare", "Contains", "ContainsAny", "ContainsFunc", "ContainsRune", "Count", "Cut", "CutPrefix", "CutSuffix", "EqualFold", "Fields", "FieldsFunc", "HasPrefix", "HasSuffix", "Index", "IndexAny", "IndexByte", "IndexFunc", "IndexRune", "Join", "LastIndex", "LastIndexAny", "LastIndexByte", "LastIndexFunc", "Map", "Repeat", "Replace", "ReplaceAll", "Split", "SplitAfter", "SplitAfterN", "SplitN", "Title", "ToLower", "ToLowerSpecial", "ToTitle", "ToTitleSpecial", "ToUpper", "ToUpperSpecial", "ToValidUTF8", "Trim", "TrimFunc", "TrimLeft", "TrimLeftFunc", "TrimPrefix", "TrimRight", "TrimRightFunc", "TrimSpace", "TrimSuffix"},
		"sync":     {"OnceFunc", "OnceValue", "OnceValues"},
		"syscall":  {"Access", "Acct", "Adjtimex", "AttachLsf", "Bind", "BindToDevice", "BytePtrFromString", "ByteSliceFromString", "Chdir", "Chmod", "Chown", "Chroot", "Clearenv", "Close", "CloseOnExec", "CmsgLen", "CmsgSpace", "Connect", "Creat", "DetachLsf", "Dup", "Dup2", "Dup3", "Environ", "EpollCreate", "EpollCreate1", "EpollCtl", "EpollWait", "Exec", "Exit", "Faccessat", "Fallocate", "Fchdir", "Fchmod", "Fchmodat", "Fchown", "Fchownat", "FcntlFlock", "Fdatasync", "Flock", "ForkExec", "Fstat", "Fstatfs", "Fsync", "Ftruncate", "Futimes", "Futimesat", "Getcwd", "Getdents", "Getegid", "Getenv", "Geteuid", "Getgid", "Getgroups", "Getpagesize", "Getpgid", "Getpgrp", "Getpid", "Getppid", "Getpriority", "Getrlimit", "Getrusage", "GetsockoptInet4Addr", "GetsockoptInt", "Gettid", "Gettimeofday", "Getuid", "Getwd", "Getxattr", "InotifyAddWatch", "InotifyInit", "InotifyInit1", "InotifyRmWatch", "Ioperm", "Iopl", "Kill", "Klogctl", "Lchown", "Link", "Listen", "Listxattr", "LsfSocket", "Lstat", "Madvise", "Mkdir", "Mkdirat", "Mkfifo", "Mknod", "Mknodat", "Mlock", "Mlockall", "Mmap", "Mount", "Mprotect", "Munlock", "Munlockall", "Munmap", "Nanosleep", "NetlinkRIB", "Open", "Openat", "ParseDirent", "ParseUnixRights", "Pause", "Pipe", "Pipe2", "PivotRoot", "Pread", "PtraceAttach", "PtraceCont", "PtraceDetach", "PtraceGetEventMsg", "PtraceGetRegs", "PtracePeekData", "PtracePeekText", "PtracePokeData", "PtracePokeText", "PtraceSetOptions", "PtraceSetRegs", "PtraceSingleStep", "PtraceSyscall", "Pwrite", "Read", "ReadDirent", "Readlink", "Reboot", "Removexattr", "Rename", "Renameat", "Rmdir", "Seek", "Select", "Sendfile", "Sendmsg", "SendmsgN", "Sendto", "SetLsfPromisc", "SetNonblock", "Setdomainname", "Setegid", "Setenv", "Seteuid", "Setfsgid", "Setfsuid", "Setgid", "Setgroups", "Sethostname", "Setpgid", "Setpriority", "Setregid", "Setresgid", "Setresuid", "Setreuid", "Setrlimit", "Setsid", "SetsockoptByte", "SetsockoptICMPv6Filter", "SetsockoptIPMreq", "SetsockoptIPMreqn", "SetsockoptIPv6Mreq", "SetsockoptInet4Addr", "SetsockoptInt", "SetsockoptLinger", "SetsockoptString", "SetsockoptTimeval", "Settimeofday", "Setuid", "Setxattr", "Shutdown", "SlicePtrFromStrings", "Socket", "Socketpair", "Splice", "StartProcess", "Stat", "Statfs", "StringBytePtr", "StringByteSlice", "StringSlicePtr", "Symlink", "Sync", "SyncFileRange", "Sysinfo", "Tee", "Tgkill", "Times", "TimespecToNsec", "TimevalToNsec", "Truncate", "Umask", "Uname", "UnixCredentials", "UnixRights", "Unlink", "Unlinkat", "Unmount", "Unsetenv", "Unshare", "Ustat", "Utime", "Utimes", "UtimesNano", "Wait4", "Write"},
		"testing":  {"AllocsPerRun", "CoverMode", "Coverage", "Init", "Main", "RegisterCover", "RunBenchmarks", "RunExamples", "RunTests", "Short", "Testing", "Verbose"},
		"time":     {"After", "Sleep", "Tick"},
		"unicode":  {"In", "Is", "IsControl", "IsDigit", "IsGraphic", "IsLetter", "IsLower", "IsMark", "IsNumber", "IsOneOf", "IsPrint", "IsPunct", "IsSpace", "IsSymbol", "IsTitle", "IsUpper", "SimpleFold", "To", "ToLower", "ToTitle", "ToUpper"},
		"unsafe":   {"Alignof", "Offsetof", "Sizeof", "String", "StringData"}}

	autoComplete = []string{
		// packages
		"strconv",
		"bytes",
		"log",
		"net",
		"testing",
		"expvar",
		"mime",
		"os",
		"unicode",
		"cmp",
		"runtime",
		"strings",
		"embed",
		"plugin",
		"flag",
		"io",
		"regexp",
		"bufio",
		"crypto",
		"encoding",
		"image",
		"path",
		"slices",
		"sync",
		"time",
		"builtin",
		"errors",
		"fmt",
		"unsafe",
		"reflect",
		"sort",
		"context",
		"html",
		"math",
		"hash",
		"maps",
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
