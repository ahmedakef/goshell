package main

import (
	"strings"

	"golang.org/x/exp/maps"
)

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
		"archive/tar":                        {},
		"archive/zip":                        {"RegisterCompressor", "RegisterDecompressor"},
		"bufio":                              {"ScanBytes", "ScanLines", "ScanRunes", "ScanWords"},
		"builtin":                            {"append", "cap", "clear", "close", "complex", "copy", "delete", "imag", "len", "make", "max", "min", "new", "panic", "print", "println", "real", "recover"},
		"bytes":                              {"Clone", "Compare", "Contains", "ContainsAny", "ContainsFunc", "ContainsRune", "Count", "Cut", "CutPrefix", "CutSuffix", "Equal", "EqualFold", "Fields", "FieldsFunc", "HasPrefix", "HasSuffix", "Index", "IndexAny", "IndexByte", "IndexFunc", "IndexRune", "Join", "LastIndex", "LastIndexAny", "LastIndexByte", "LastIndexFunc", "Map", "Repeat", "Replace", "ReplaceAll", "Runes", "Split", "SplitAfter", "SplitAfterN", "SplitN", "Title", "ToLower", "ToLowerSpecial", "ToTitle", "ToTitleSpecial", "ToUpper", "ToUpperSpecial", "ToValidUTF8", "Trim", "TrimFunc", "TrimLeft", "TrimLeftFunc", "TrimPrefix", "TrimRight", "TrimRightFunc", "TrimSpace", "TrimSuffix"},
		"cmp":                                {"Compare", "Less", "Or"},
		"compress/bzip2":                     {"NewReader"},
		"compress/flate":                     {"NewReader", "NewReaderDict"},
		"compress/gzip":                      {},
		"compress/lzw":                       {"NewReader", "NewWriter"},
		"compress/zlib":                      {"NewReader", "NewReaderDict"},
		"container/heap":                     {"Fix", "Init", "Pop", "Push", "Remove"},
		"container/list":                     {},
		"container/ring":                     {},
		"context":                            {"AfterFunc", "Cause", "WithCancel", "WithCancelCause", "WithDeadline", "WithDeadlineCause", "WithTimeout", "WithTimeoutCause"},
		"crypto":                             {"RegisterHash"},
		"crypto/aes":                         {"NewCipher"},
		"crypto/cipher":                      {},
		"crypto/des":                         {"NewCipher", "NewTripleDESCipher"},
		"crypto/dsa":                         {"GenerateKey", "GenerateParameters", "Sign", "Verify"},
		"crypto/ecdh":                        {},
		"crypto/ecdsa":                       {"Sign", "SignASN1", "Verify", "VerifyASN1"},
		"crypto/ed25519":                     {"GenerateKey", "Sign", "Verify", "VerifyWithOptions"},
		"crypto/elliptic":                    {"GenerateKey", "Marshal", "MarshalCompressed", "Unmarshal", "UnmarshalCompressed"},
		"crypto/hmac":                        {"Equal", "New"},
		"crypto/internal/alias":              {"AnyOverlap", "InexactOverlap"},
		"crypto/internal/bigmod":             {},
		"crypto/internal/boring":             {"DecryptRSANoPadding", "DecryptRSAOAEP", "DecryptRSAPKCS1", "ECDH", "EncryptRSANoPadding", "EncryptRSAOAEP", "EncryptRSAPKCS1", "NewAESCipher", "NewGCMTLS", "NewHMAC", "NewSHA1", "NewSHA224", "NewSHA256", "NewSHA384", "NewSHA512", "SHA1", "SHA224", "SHA256", "SHA384", "SHA512", "SignMarshalECDSA", "SignRSAPKCS1v15", "SignRSAPSS", "Unreachable", "UnreachableExceptTests", "VerifyECDSA", "VerifyRSAPKCS1v15", "VerifyRSAPSS"},
		"crypto/internal/boring/bbig":        {"Dec", "Enc"},
		"crypto/internal/boring/bcache":      {},
		"crypto/internal/boring/sig":         {"BoringCrypto", "FIPSOnly", "StandardCrypto"},
		"crypto/internal/edwards25519":       {},
		"crypto/internal/edwards25519/field": {},
		"crypto/internal/nistec":             {"P256OrdInverse"},
		"crypto/internal/nistec/fiat":        {},
		"crypto/internal/randutil":           {"MaybeReadByte"},
		"crypto/md5":                         {"New", "Sum"},
		"crypto/rand":                        {"Int", "Prime", "Read"},
		"crypto/rc4":                         {},
		"crypto/rsa":                         {"DecryptOAEP", "DecryptPKCS1v15", "DecryptPKCS1v15SessionKey", "EncryptOAEP", "EncryptPKCS1v15", "SignPKCS1v15", "SignPSS", "VerifyPKCS1v15", "VerifyPSS"},
		"crypto/sha1":                        {"New", "Sum"},
		"crypto/sha256":                      {"New", "New224", "Sum224", "Sum256"},
		"crypto/sha512":                      {"New", "New384", "New512_224", "New512_256", "Sum384", "Sum512", "Sum512_224", "Sum512_256"},
		"crypto/subtle":                      {"ConstantTimeByteEq", "ConstantTimeCompare", "ConstantTimeCopy", "ConstantTimeEq", "ConstantTimeLessOrEq", "ConstantTimeSelect", "XORBytes"},
		"crypto/tls":                         {"CipherSuiteName", "Listen", "NewListener", "VersionName"},
		"crypto/x509":                        {"CreateCertificate", "CreateCertificateRequest", "CreateRevocationList", "DecryptPEMBlock", "EncryptPEMBlock", "IsEncryptedPEMBlock", "MarshalECPrivateKey", "MarshalPKCS1PrivateKey", "MarshalPKCS1PublicKey", "MarshalPKCS8PrivateKey", "MarshalPKIXPublicKey", "ParseCRL", "ParseDERCRL", "ParseECPrivateKey", "ParsePKCS1PrivateKey", "ParsePKCS1PublicKey", "ParsePKCS8PrivateKey", "ParsePKIXPublicKey", "SetFallbackRoots"},
		"crypto/x509/internal/macos":         {"CFArrayAppendValue", "CFArrayGetCount", "CFDataGetBytePtr", "CFDataGetLength", "CFDataToSlice", "CFEqual", "CFErrorGetCode", "CFNumberGetValue", "CFRelease", "CFStringToString", "ReleaseCFArray", "SecCertificateCopyData", "SecTrustEvaluateWithError", "SecTrustGetCertificateCount", "SecTrustGetResult", "SecTrustSetVerifyDate"},
		"crypto/x509/pkix":                   {},
		"database/sql":                       {"Drivers", "Register"},
		"database/sql/driver":                {"IsScanValue", "IsValue"},
		"debug/buildinfo":                    {},
		"debug/dwarf":                        {},
		"debug/elf":                          {"R_INFO", "R_INFO32", "R_SYM32", "R_SYM64", "R_TYPE32", "R_TYPE64", "ST_INFO"},
		"debug/gosym":                        {},
		"debug/macho":                        {},
		"debug/pe":                           {},
		"debug/plan9obj":                     {},
		"embed":                              {},
		"encoding":                           {},
		"encoding/ascii85":                   {"Decode", "Encode", "MaxEncodedLen", "NewDecoder", "NewEncoder"},
		"encoding/asn1":                      {"Marshal", "MarshalWithParams", "Unmarshal", "UnmarshalWithParams"},
		"encoding/base32":                    {"NewDecoder", "NewEncoder"},
		"encoding/base64":                    {"NewDecoder", "NewEncoder"},
		"encoding/binary":                    {"AppendUvarint", "AppendVarint", "PutUvarint", "PutVarint", "Read", "ReadUvarint", "ReadVarint", "Size", "Uvarint", "Varint", "Write"},
		"encoding/csv":                       {},
		"encoding/gob":                       {"Register", "RegisterName"},
		"encoding/hex":                       {"AppendDecode", "AppendEncode", "Decode", "DecodeString", "DecodedLen", "Dump", "Dumper", "Encode", "EncodeToString", "EncodedLen", "NewDecoder", "NewEncoder"},
		"encoding/json":                      {"Compact", "HTMLEscape", "Indent", "Marshal", "MarshalIndent", "Unmarshal", "Valid"},
		"encoding/pem":                       {"Encode", "EncodeToMemory"},
		"encoding/xml":                       {"Escape", "EscapeText", "Marshal", "MarshalIndent", "Unmarshal"},
		"errors":                             {"As", "Is", "Join", "New", "Unwrap"},
		"expvar":                             {"Do", "Handler", "Publish"},
		"flag":                               {"Arg", "Args", "Bool", "BoolFunc", "BoolVar", "Duration", "DurationVar", "Float64", "Float64Var", "Func", "Int", "Int64", "Int64Var", "IntVar", "NArg", "NFlag", "Parse", "Parsed", "PrintDefaults", "Set", "String", "StringVar", "TextVar", "Uint", "Uint64", "Uint64Var", "UintVar", "UnquoteUsage", "Var", "Visit", "VisitAll"},
		"fmt":                                {"Append", "Appendf", "Appendln", "Errorf", "FormatString", "Fprint", "Fprintf", "Fprintln", "Fscan", "Fscanf", "Fscanln", "Print", "Printf", "Println", "Scan", "Scanf", "Scanln", "Sprint", "Sprintf", "Sprintln", "Sscan", "Sscanf", "Sscanln"},
		"go/ast":                             {"FileExports", "FilterDecl", "FilterFile", "FilterPackage", "Fprint", "Inspect", "IsExported", "IsGenerated", "NotNilFilter", "PackageExports", "Print", "SortImports", "Walk"},
		"go/build":                           {"ArchChar", "IsLocalImport"},
		"go/build/constraint":                {"GoVersion", "IsGoBuild", "IsPlusBuild", "PlusBuildLines"},
		"go/constant":                        {"BitLen", "BoolVal", "Bytes", "Compare", "Float32Val", "Float64Val", "Int64Val", "Sign", "StringVal", "Uint64Val", "Val"},
		"go/doc":                             {"IsPredeclared", "Synopsis", "ToHTML", "ToText"},
		"go/doc/comment":                     {"DefaultLookupPackage"},
		"go/format":                          {"Node", "Source"},
		"go/importer":                        {"Default", "For", "ForCompiler"},
		"go/internal/gccgoimporter":          {},
		"go/internal/gcimporter":             {"FindExportData", "FindPkg", "Import"},
		"go/internal/srcimporter":            {},
		"go/internal/typeparams":             {"PackIndexExpr"},
		"go/parser":                          {"ParseDir", "ParseExpr", "ParseExprFrom", "ParseFile"},
		"go/printer":                         {"Fprint"},
		"go/scanner":                         {"PrintError"},
		"go/token":                           {"IsExported", "IsIdentifier", "IsKeyword"},
		"go/types":                           {"AssertableTo", "AssignableTo", "CheckExpr", "Comparable", "ConvertibleTo", "DefPredeclaredTestFuncs", "ExprString", "Id", "Identical", "IdenticalIgnoreTags", "Implements", "IsInterface", "ObjectString", "Satisfies", "SelectionString", "TypeString", "WriteExpr", "WriteSignature", "WriteType"},
		"go/version":                         {"Compare", "IsValid", "Lang"},
		"hash":                               {},
		"hash/adler32":                       {"Checksum", "New"},
		"hash/crc32":                         {"Checksum", "ChecksumIEEE", "New", "NewIEEE", "Update"},
		"hash/crc64":                         {"Checksum", "New", "Update"},
		"hash/fnv":                           {"New128", "New128a", "New32", "New32a", "New64", "New64a"},
		"hash/maphash":                       {"Bytes", "String"},
		"html":                               {"EscapeString", "UnescapeString"},
		"html/template":                      {"HTMLEscape", "HTMLEscapeString", "HTMLEscaper", "IsTrue", "JSEscape", "JSEscapeString", "JSEscaper", "URLQueryEscaper"},
		"image":                              {"RegisterFormat"},
		"image/color":                        {"CMYKToRGB", "RGBToCMYK", "RGBToYCbCr", "YCbCrToRGB"},
		"image/color/palette":                {},
		"image/draw":                         {"Draw", "DrawMask"},
		"image/gif":                          {"Decode", "DecodeConfig", "Encode", "EncodeAll"},
		"image/internal/imageutil":           {"DrawYCbCr"},
		"image/jpeg":                         {"Decode", "DecodeConfig", "Encode"},
		"image/png":                          {"Decode", "DecodeConfig", "Encode"},
		"index/suffixarray":                  {},
		"internal/abi":                       {"CommonSize", "FuncPCABI0", "FuncPCABIInternal", "StructFieldSize", "TFlagOff", "UncommonSize", "UseInterfaceSwitchCache"},
		"internal/bisect":                    {"AppendMarker", "CutMarker", "Hash", "Marker", "PrintMarker"},
		"internal/buildcfg":                  {"Check", "GOGOARCH", "Getgoextlinkenabled"},
		"internal/bytealg":                   {"Compare", "Count", "CountString", "Cutover", "Equal", "HashStr", "HashStrRev", "Index", "IndexByte", "IndexByteString", "IndexRabinKarp", "IndexString", "LastIndexByte", "LastIndexByteString", "LastIndexRabinKarp", "MakeNoZero"},
		"internal/cfg":                       {},
		"internal/chacha8rand":               {"Marshal", "Unmarshal"},
		"internal/coverage":                  {"HardCodedPkgID", "Round4"},
		"internal/coverage/calloc":           {},
		"internal/coverage/cformat":          {},
		"internal/coverage/cmerge":           {"SaturatingAdd"},
		"internal/coverage/decodecounter":    {},
		"internal/coverage/decodemeta":       {},
		"internal/coverage/encodecounter":    {},
		"internal/coverage/encodemeta":       {"HashFuncDesc"},
		"internal/coverage/pods":             {},
		"internal/coverage/rtcov":            {},
		"internal/coverage/slicereader":      {},
		"internal/coverage/slicewriter":      {},
		"internal/coverage/stringtab":        {},
		"internal/coverage/uleb128":          {"AppendUleb128"},
		"internal/cpu":                       {"Initialize", "Name"},
		"internal/dag":                       {},
		"internal/diff":                      {"Diff"},
		"internal/fmtsort":                   {},
		"internal/fuzz":                      {"CheckCorpus", "CoordinateFuzzing", "ResetCoverage", "RunFuzzWorker", "SnapshotCoverage"},
		"internal/goarch":                    {},
		"internal/godebug":                   {},
		"internal/godebugs":                  {},
		"internal/goexperiment":              {},
		"internal/goos":                      {},
		"internal/goroot":                    {"IsStandardPackage"},
		"internal/gover":                     {"CmpInt", "Compare", "DecInt", "IsLang", "IsValid", "Lang", "Max"},
		"internal/goversion":                 {},
		"internal/intern":                    {},
		"internal/itoa":                      {"Itoa", "Uitoa", "Uitox"},
		"internal/lazyregexp":                {},
		"internal/lazytemplate":              {},
		"internal/nettrace":                  {},
		"internal/obscuretestdata":           {"DecodeToTempFile", "ReadFile", "Rot13"},
		"internal/oserror":                   {},
		"internal/pkgbits":                   {},
		"internal/platform":                  {"ASanSupported", "Broken", "BuildModeSupported", "CgoSupported", "DefaultPIE", "ExecutableHasDWARF", "FirstClass", "FuzzInstrumented", "FuzzSupported", "InternalLinkPIESupported", "MSanSupported", "MustLinkExternal", "RaceDetectorSupported"},
		"internal/poll":                      {"CopyFileRange", "DupCloseOnExec", "IsPollDescriptor", "SendFile", "Splice"},
		"internal/profile":                   {},
		"internal/race":                      {"Acquire", "Disable", "Enable", "Errors", "Read", "ReadRange", "Release", "ReleaseMerge", "Write", "WriteRange"},
		"internal/reflectlite":               {"Swapper"},
		"internal/safefilepath":              {"FromFS"},
		"internal/saferio":                   {"ReadData", "ReadDataAt", "SliceCap", "SliceCapWithSize"},
		"internal/singleflight":              {},
		"internal/syscall/execenv":           {"Default"},
		"internal/syscall/unix":              {"CopyFileRange", "Eaccess", "Fcntl", "Fstatat", "GetRandom", "HasNonblockFlag", "IsNonblock", "KernelVersion", "Openat", "PidFDSendSignal", "RecvfromInet4", "RecvfromInet6", "RecvmsgInet4", "RecvmsgInet6", "SendmsgNInet4", "SendmsgNInet6", "SendtoInet4", "SendtoInet6", "Unlinkat"},
		"internal/syscall/windows":           {"AdjustTokenPrivileges", "CreateEnvironmentBlock", "CreateEvent", "DestroyEnvironmentBlock", "DuplicateTokenEx", "ErrorLoadingGetTempPath2", "GetACP", "GetAdaptersAddresses", "GetComputerNameEx", "GetConsoleCP", "GetCurrentThread", "GetFileInformationByHandleEx", "GetFinalPathNameByHandle", "GetModuleFileName", "GetProcessMemoryInfo", "GetProfilesDirectory", "GetSystemDirectory", "GetTempPath2", "GetVolumeInformationByHandle", "GetVolumeNameForVolumeMountPoint", "ImpersonateSelf", "LockFileEx", "LookupPrivilegeValue", "Module32First", "Module32Next", "MoveFileEx", "MultiByteToWideChar", "NetShareAdd", "NetShareDel", "NetUserGetLocalGroups", "OpenSCManager", "OpenService", "OpenThreadToken", "ProcessPrng", "QueryServiceStatus", "Rename", "RevertToSelf", "RtlLookupFunctionEntry", "RtlVirtualUnwind", "SetFileInformationByHandle", "SetTokenInformation", "UTF16PtrToString", "UnlockFileEx", "VirtualQuery", "WSARecvMsg", "WSASendMsg", "WSASendtoInet4", "WSASendtoInet6", "WSASocket"},
		"internal/syscall/windows/registry":  {"DeleteKey", "ExpandString"},
		"internal/syscall/windows/sysdll":    {"Add"},
		"internal/sysinfo":                   {"CPUName"},
		"internal/testenv":                   {"Builder", "CPUIsSlow", "CanInternalLink", "CleanCmdEnv", "Command", "CommandContext", "GOROOT", "GoTool", "GoToolPath", "HasCGO", "HasExternalNetwork", "HasGoBuild", "HasGoRun", "HasLink", "HasParallelism", "HasSrc", "HasSymlink", "MustHaveBuildMode", "MustHaveCGO", "MustHaveExec", "MustHaveExecPath", "MustHaveExternalNetwork", "MustHaveGoBuild", "MustHaveGoRun", "MustHaveLink", "MustHaveParallelism", "MustHaveSymlink", "MustInternalLink", "OptimizationOff", "SkipFlaky", "SkipFlakyNet", "SkipIfOptimizationOff", "SkipIfShortAndSlow", "SyscallIsNotSupported", "WriteImportcfg"},
		"internal/testlog":                   {"Getenv", "Open", "PanicOnExit0", "SetLogger", "SetPanicOnExit0", "Stat"},
		"internal/testpty":                   {"Open"},
		"internal/trace":                     {"GoroutineStats", "IsSystemGoroutine", "MutatorUtilization", "MutatorUtilizationV2", "Print", "PrintEvent", "ReadVersion", "RelatedGoroutines", "RelatedGoroutinesV2"},
		"internal/trace/traceviewer":         {"BuildProfile", "MMUHandlerFunc", "MainHandler", "SVGProfileHandlerFunc", "StaticHandler", "TraceHandler", "WalkStackFrames"},
		"internal/trace/traceviewer/format":  {},
		"internal/trace/v2":                  {},
		"internal/trace/v2/event":            {"Names"},
		"internal/trace/v2/event/go122":      {"EventString", "Specs"},
		"internal/trace/v2/internal/testgen/go122": {"Main"},
		"internal/trace/v2/raw":                    {},
		"internal/trace/v2/testtrace":              {},
		"internal/trace/v2/version":                {"WriteHeader"},
		"internal/txtar":                           {"Format"},
		"internal/types/errors":                    {},
		"internal/unsafeheader":                    {},
		"internal/xcoff":                           {},
		"internal/zstd":                            {},
		"io":                                       {"Copy", "CopyBuffer", "CopyN", "Pipe", "ReadAll", "ReadAtLeast", "ReadFull", "WriteString"},
		"io/fs":                                    {"FormatDirEntry", "FormatFileInfo", "Glob", "ReadFile", "ValidPath", "WalkDir"},
		"io/ioutil":                                {"NopCloser", "ReadAll", "ReadDir", "ReadFile", "TempDir", "TempFile", "WriteFile"},
		"log":                                      {"Fatal", "Fatalf", "Fatalln", "Flags", "Output", "Panic", "Panicf", "Panicln", "Prefix", "Print", "Printf", "Println", "SetFlags", "SetOutput", "SetPrefix", "Writer"},
		"log/internal":                             {},
		"log/slog":                                 {"Debug", "DebugContext", "Error", "ErrorContext", "Info", "InfoContext", "Log", "LogAttrs", "NewLogLogger", "SetDefault", "Warn", "WarnContext"},
		"log/slog/internal":                        {},
		"log/slog/internal/benchmarks":             {},
		"log/slog/internal/buffer":                 {},
		"log/slog/internal/slogtest":               {"RemoveTime"},
		"log/syslog":                               {"NewLogger"},
		"maps":                                     {"Clone", "Copy", "DeleteFunc", "Equal", "EqualFunc"},
		"math":                                     {"Abs", "Acos", "Acosh", "Asin", "Asinh", "Atan", "Atan2", "Atanh", "Cbrt", "Ceil", "Copysign", "Cos", "Cosh", "Dim", "Erf", "Erfc", "Erfcinv", "Erfinv", "Exp", "Exp2", "Expm1", "FMA", "Float32bits", "Float32frombits", "Float64bits", "Float64frombits", "Floor", "Frexp", "Gamma", "Hypot", "Ilogb", "Inf", "IsInf", "IsNaN", "J0", "J1", "Jn", "Ldexp", "Lgamma", "Log", "Log10", "Log1p", "Log2", "Logb", "Max", "Min", "Mod", "Modf", "NaN", "Nextafter", "Nextafter32", "Pow", "Pow10", "Remainder", "Round", "RoundToEven", "Signbit", "Sin", "Sincos", "Sinh", "Sqrt", "Tan", "Tanh", "Trunc", "Y0", "Y1", "Yn"},
		"math/big":                                 {"Jacobi"},
		"math/bits":                                {"Add", "Add32", "Add64", "Div", "Div32", "Div64", "LeadingZeros", "LeadingZeros16", "LeadingZeros32", "LeadingZeros64", "LeadingZeros8", "Len", "Len16", "Len32", "Len64", "Len8", "Mul", "Mul32", "Mul64", "OnesCount", "OnesCount16", "OnesCount32", "OnesCount64", "OnesCount8", "Rem", "Rem32", "Rem64", "Reverse", "Reverse16", "Reverse32", "Reverse64", "Reverse8", "ReverseBytes", "ReverseBytes16", "ReverseBytes32", "ReverseBytes64", "RotateLeft", "RotateLeft16", "RotateLeft32", "RotateLeft64", "RotateLeft8", "Sub", "Sub32", "Sub64", "TrailingZeros", "TrailingZeros16", "TrailingZeros32", "TrailingZeros64", "TrailingZeros8"},
		"math/cmplx":                               {"Abs", "Acos", "Acosh", "Asin", "Asinh", "Atan", "Atanh", "Conj", "Cos", "Cosh", "Cot", "Exp", "Inf", "IsInf", "IsNaN", "Log", "Log10", "NaN", "Phase", "Polar", "Pow", "Rect", "Sin", "Sinh", "Sqrt", "Tan", "Tanh"},
		"math/rand":                                {"ExpFloat64", "Float32", "Float64", "Int", "Int31", "Int31n", "Int63", "Int63n", "Intn", "NormFloat64", "Perm", "Read", "Seed", "Shuffle", "Uint32", "Uint64"},
		"math/rand/v2":                             {"ExpFloat64", "Float32", "Float64", "Int", "Int32", "Int32N", "Int64", "Int64N", "IntN", "N", "NormFloat64", "Perm", "Shuffle", "Uint32", "Uint32N", "Uint64", "Uint64N", "UintN"},
		"mime":                                     {"AddExtensionType", "ExtensionsByType", "FormatMediaType", "ParseMediaType", "TypeByExtension"},
		"mime/multipart":                           {},
		"mime/quotedprintable":                     {},
		"net":                                      {"JoinHostPort", "LookupAddr", "LookupCNAME", "LookupHost", "LookupPort", "LookupTXT", "ParseCIDR", "Pipe", "SplitHostPort"},
		"net/http":                                 {"CanonicalHeaderKey", "DetectContentType", "Error", "Handle", "HandleFunc", "ListenAndServe", "ListenAndServeTLS", "MaxBytesReader", "NotFound", "ParseHTTPVersion", "ParseTime", "ProxyFromEnvironment", "ProxyURL", "Redirect", "Serve", "ServeContent", "ServeFile", "ServeFileFS", "ServeTLS", "SetCookie", "StatusText"},
		"net/http/cgi":                             {"Request", "RequestFromMap", "Serve"},
		"net/http/cookiejar":                       {},
		"net/http/fcgi":                            {"ProcessEnv", "Serve"},
		"net/http/httptest":                        {"NewRequest"},
		"net/http/httptrace":                       {"WithClientTrace"},
		"net/http/httputil":                        {"DumpRequest", "DumpRequestOut", "DumpResponse", "NewChunkedReader", "NewChunkedWriter"},
		"net/http/internal":                        {"NewChunkedReader", "NewChunkedWriter"},
		"net/http/internal/ascii":                  {"EqualFold", "Is", "IsPrint", "ToLower"},
		"net/http/internal/testcert":               {},
		"net/http/pprof":                           {"Cmdline", "Handler", "Index", "Profile", "Symbol", "Trace"},
		"net/internal/socktest":                    {},
		"net/mail":                                 {"ParseDate"},
		"net/netip":                                {},
		"net/rpc":                                  {"Accept", "HandleHTTP", "Register", "RegisterName", "ServeCodec", "ServeConn", "ServeRequest"},
		"net/rpc/jsonrpc":                          {},
		"net/smtp":                                 {"SendMail"},
		"net/textproto":                            {"CanonicalMIMEHeaderKey", "TrimBytes", "TrimString"},
		"net/url":                                  {"JoinPath", "PathEscape", "PathUnescape", "QueryEscape", "QueryUnescape"},
		"os":                                       {"Chdir", "Chmod", "Chown", "Chtimes", "Clearenv", "DirFS", "Environ", "Executable", "Exit", "Expand", "ExpandEnv", "Getegid", "Getenv", "Geteuid", "Getgid", "Getgroups", "Getpagesize", "Getpid", "Getppid", "Getuid", "Getwd", "Hostname", "IsExist", "IsNotExist", "IsPathSeparator", "IsPermission", "IsTimeout", "Lchown", "Link", "LookupEnv", "Mkdir", "MkdirAll", "MkdirTemp", "NewSyscallError", "Pipe", "ReadFile", "Readlink", "Remove", "RemoveAll", "Rename", "SameFile", "Setenv", "Symlink", "TempDir", "Truncate", "Unsetenv", "UserCacheDir", "UserConfigDir", "UserHomeDir", "WriteFile"},
		"os/exec":                                  {"LookPath"},
		"os/exec/internal/fdtest":                  {"Exists"},
		"os/signal":                                {"Ignore", "Ignored", "Notify", "NotifyContext", "Reset", "Stop"},
		"os/user":                                  {},
		"path":                                     {"Base", "Clean", "Dir", "Ext", "IsAbs", "Join", "Match", "Split"},
		"path/filepath":                            {"Abs", "Base", "Clean", "Dir", "EvalSymlinks", "Ext", "FromSlash", "Glob", "HasPrefix", "IsAbs", "IsLocal", "Join", "Match", "Rel", "Split", "SplitList", "ToSlash", "VolumeName", "Walk", "WalkDir"},
		"plugin":                                   {},
		"reflect":                                  {"Copy", "DeepEqual", "Swapper"},
		"reflect/internal/example1":                {},
		"reflect/internal/example2":                {},
		"regexp":                                   {"Match", "MatchReader", "MatchString", "QuoteMeta"},
		"regexp/syntax":                            {"IsWordChar"},
		"runtime":                                  {"BlockProfile", "Breakpoint", "CPUProfile", "Caller", "Callers", "GC", "GOMAXPROCS", "GOROOT", "Goexit", "GoroutineProfile", "Gosched", "KeepAlive", "LockOSThread", "MemProfile", "MutexProfile", "NumCPU", "NumCgoCall", "NumGoroutine", "ReadMemStats", "ReadTrace", "SetBlockProfileRate", "SetCPUProfileRate", "SetCgoTraceback", "SetFinalizer", "SetMutexProfileFraction", "Stack", "StartTrace", "StopTrace", "ThreadCreateProfile", "UnlockOSThread", "Version"},
		"runtime/cgo":                              {},
		"runtime/coverage":                         {"ClearCounters", "WriteCounters", "WriteCountersDir", "WriteMeta", "WriteMetaDir"},
		"runtime/debug":                            {"FreeOSMemory", "PrintStack", "ReadGCStats", "SetGCPercent", "SetMaxStack", "SetMaxThreads", "SetMemoryLimit", "SetPanicOnFault", "SetTraceback", "Stack", "WriteHeapDump"},
		"runtime/internal/atomic":                  {"And", "And32", "And64", "And8", "Anduintptr", "Cas", "Cas64", "CasRel", "Casint32", "Casint64", "Casp1", "Casuintptr", "Load", "Load64", "Load8", "LoadAcq", "LoadAcq64", "LoadAcquintptr", "Loadint32", "Loadint64", "Loadp", "Loaduint", "Loaduintptr", "Or", "Or32", "Or64", "Or8", "Oruintptr", "Store", "Store64", "Store8", "StoreRel", "StoreRel64", "StoreReluintptr", "Storeint32", "Storeint64", "StorepNoWB", "Storeuintptr", "Xadd", "Xadd64", "Xaddint32", "Xaddint64", "Xadduintptr", "Xchg", "Xchg64", "Xchgint32", "Xchgint64", "Xchguintptr"},
		"runtime/internal/math":                    {"Add64", "Mul64", "MulUintptr"},
		"runtime/internal/startlinetest":           {"AsmFunc"},
		"runtime/internal/sys":                     {"Bswap32", "Bswap64", "LeadingZeros64", "LeadingZeros8", "Len64", "Len8", "OnesCount64", "Prefetch", "PrefetchStreamed", "TrailingZeros32", "TrailingZeros64", "TrailingZeros8"},
		"runtime/internal/syscall":                 {"EpollCreate1", "EpollCtl", "EpollWait", "Syscall6"},
		"runtime/metrics":                          {"Read"},
		"runtime/pprof":                            {"Do", "ForLabels", "Label", "SetGoroutineLabels", "StartCPUProfile", "StopCPUProfile", "WithLabels", "WriteHeapProfile"},
		"runtime/race":                             {},
		"runtime/race/internal/amd64v1":            {},
		"runtime/trace":                            {"IsEnabled", "Log", "Logf", "Start", "Stop", "WithRegion"},
		"slices":                                   {"BinarySearch", "BinarySearchFunc", "Clip", "Clone", "Compact", "CompactFunc", "Compare", "CompareFunc", "Concat", "Contains", "ContainsFunc", "Delete", "DeleteFunc", "Equal", "EqualFunc", "Grow", "Index", "IndexFunc", "Insert", "IsSorted", "IsSortedFunc", "Max", "MaxFunc", "Min", "MinFunc", "Replace", "Reverse", "Sort", "SortFunc", "SortStableFunc"},
		"sort":                                     {"Find", "Float64s", "Float64sAreSorted", "Ints", "IntsAreSorted", "IsSorted", "Search", "SearchFloat64s", "SearchInts", "SearchStrings", "Slice", "SliceIsSorted", "SliceStable", "Sort", "Stable", "Strings", "StringsAreSorted"},
		"strconv":                                  {"AppendBool", "AppendFloat", "AppendInt", "AppendQuote", "AppendQuoteRune", "AppendQuoteRuneToASCII", "AppendQuoteRuneToGraphic", "AppendQuoteToASCII", "AppendQuoteToGraphic", "AppendUint", "Atoi", "CanBackquote", "FormatBool", "FormatComplex", "FormatFloat", "FormatInt", "FormatUint", "IsGraphic", "IsPrint", "Itoa", "ParseBool", "ParseComplex", "ParseFloat", "ParseInt", "ParseUint", "Quote", "QuoteRune", "QuoteRuneToASCII", "QuoteRuneToGraphic", "QuoteToASCII", "QuoteToGraphic", "QuotedPrefix", "Unquote", "UnquoteChar"},
		"strings":                                  {"Clone", "Compare", "Contains", "ContainsAny", "ContainsFunc", "ContainsRune", "Count", "Cut", "CutPrefix", "CutSuffix", "EqualFold", "Fields", "FieldsFunc", "HasPrefix", "HasSuffix", "Index", "IndexAny", "IndexByte", "IndexFunc", "IndexRune", "Join", "LastIndex", "LastIndexAny", "LastIndexByte", "LastIndexFunc", "Map", "Repeat", "Replace", "ReplaceAll", "Split", "SplitAfter", "SplitAfterN", "SplitN", "Title", "ToLower", "ToLowerSpecial", "ToTitle", "ToTitleSpecial", "ToUpper", "ToUpperSpecial", "ToValidUTF8", "Trim", "TrimFunc", "TrimLeft", "TrimLeftFunc", "TrimPrefix", "TrimRight", "TrimRightFunc", "TrimSpace", "TrimSuffix"},
		"sync":                                     {"OnceFunc", "OnceValue", "OnceValues"},
		"sync/atomic":                              {"AddInt32", "AddInt64", "AddUint32", "AddUint64", "AddUintptr", "CompareAndSwapInt32", "CompareAndSwapInt64", "CompareAndSwapPointer", "CompareAndSwapUint32", "CompareAndSwapUint64", "CompareAndSwapUintptr", "LoadInt32", "LoadInt64", "LoadPointer", "LoadUint32", "LoadUint64", "LoadUintptr", "StoreInt32", "StoreInt64", "StorePointer", "StoreUint32", "StoreUint64", "StoreUintptr", "SwapInt32", "SwapInt64", "SwapPointer", "SwapUint32", "SwapUint64", "SwapUintptr"},
		"syscall":                                  {"Access", "Acct", "Adjtimex", "AttachLsf", "Bind", "BindToDevice", "BytePtrFromString", "ByteSliceFromString", "Chdir", "Chmod", "Chown", "Chroot", "Clearenv", "Close", "CloseOnExec", "CmsgLen", "CmsgSpace", "Connect", "Creat", "DetachLsf", "Dup", "Dup2", "Dup3", "Environ", "EpollCreate", "EpollCreate1", "EpollCtl", "EpollWait", "Exec", "Exit", "Faccessat", "Fallocate", "Fchdir", "Fchmod", "Fchmodat", "Fchown", "Fchownat", "FcntlFlock", "Fdatasync", "Flock", "ForkExec", "Fstat", "Fstatfs", "Fsync", "Ftruncate", "Futimes", "Futimesat", "Getcwd", "Getdents", "Getegid", "Getenv", "Geteuid", "Getgid", "Getgroups", "Getpagesize", "Getpgid", "Getpgrp", "Getpid", "Getppid", "Getpriority", "Getrlimit", "Getrusage", "GetsockoptInet4Addr", "GetsockoptInt", "Gettid", "Gettimeofday", "Getuid", "Getwd", "Getxattr", "InotifyAddWatch", "InotifyInit", "InotifyInit1", "InotifyRmWatch", "Ioperm", "Iopl", "Kill", "Klogctl", "Lchown", "Link", "Listen", "Listxattr", "LsfSocket", "Lstat", "Madvise", "Mkdir", "Mkdirat", "Mkfifo", "Mknod", "Mknodat", "Mlock", "Mlockall", "Mmap", "Mount", "Mprotect", "Munlock", "Munlockall", "Munmap", "Nanosleep", "NetlinkRIB", "Open", "Openat", "ParseDirent", "ParseUnixRights", "Pause", "Pipe", "Pipe2", "PivotRoot", "Pread", "PtraceAttach", "PtraceCont", "PtraceDetach", "PtraceGetEventMsg", "PtraceGetRegs", "PtracePeekData", "PtracePeekText", "PtracePokeData", "PtracePokeText", "PtraceSetOptions", "PtraceSetRegs", "PtraceSingleStep", "PtraceSyscall", "Pwrite", "Read", "ReadDirent", "Readlink", "Reboot", "Removexattr", "Rename", "Renameat", "Rmdir", "Seek", "Select", "Sendfile", "Sendmsg", "SendmsgN", "Sendto", "SetLsfPromisc", "SetNonblock", "Setdomainname", "Setegid", "Setenv", "Seteuid", "Setfsgid", "Setfsuid", "Setgid", "Setgroups", "Sethostname", "Setpgid", "Setpriority", "Setregid", "Setresgid", "Setresuid", "Setreuid", "Setrlimit", "Setsid", "SetsockoptByte", "SetsockoptICMPv6Filter", "SetsockoptIPMreq", "SetsockoptIPMreqn", "SetsockoptIPv6Mreq", "SetsockoptInet4Addr", "SetsockoptInt", "SetsockoptLinger", "SetsockoptString", "SetsockoptTimeval", "Settimeofday", "Setuid", "Setxattr", "Shutdown", "SlicePtrFromStrings", "Socket", "Socketpair", "Splice", "StartProcess", "Stat", "Statfs", "StringBytePtr", "StringByteSlice", "StringSlicePtr", "Symlink", "Sync", "SyncFileRange", "Sysinfo", "Tee", "Tgkill", "Times", "TimespecToNsec", "TimevalToNsec", "Truncate", "Umask", "Uname", "UnixCredentials", "UnixRights", "Unlink", "Unlinkat", "Unmount", "Unsetenv", "Unshare", "Ustat", "Utime", "Utimes", "UtimesNano", "Wait4", "Write"},
		"syscall/js":                               {"CopyBytesToGo", "CopyBytesToJS"},
		"testing":                                  {"AllocsPerRun", "CoverMode", "Coverage", "Init", "Main", "RegisterCover", "RunBenchmarks", "RunExamples", "RunTests", "Short", "Testing", "Verbose"},
		"testing/fstest":                           {"TestFS"},
		"testing/internal/testdeps":                {},
		"testing/iotest":                           {"DataErrReader", "ErrReader", "HalfReader", "NewReadLogger", "NewWriteLogger", "OneByteReader", "TestReader", "TimeoutReader", "TruncateWriter"},
		"testing/quick":                            {"Check", "CheckEqual", "Value"},
		"testing/slogtest":                         {"Run", "TestHandler"},
		"text/scanner":                             {"TokenString"},
		"text/tabwriter":                           {},
		"text/template":                            {"HTMLEscape", "HTMLEscapeString", "HTMLEscaper", "IsTrue", "JSEscape", "JSEscapeString", "JSEscaper", "URLQueryEscaper"},
		"text/template/parse":                      {"IsEmptyTree", "Parse"},
		"time":                                     {"After", "Sleep", "Tick"},
		"time/tzdata":                              {},
		"unicode":                                  {"In", "Is", "IsControl", "IsDigit", "IsGraphic", "IsLetter", "IsLower", "IsMark", "IsNumber", "IsOneOf", "IsPrint", "IsPunct", "IsSpace", "IsSymbol", "IsTitle", "IsUpper", "SimpleFold", "To", "ToLower", "ToTitle", "ToUpper"},
		"unicode/utf16":                            {"AppendRune", "Decode", "DecodeRune", "Encode", "EncodeRune", "IsSurrogate"},
		"unicode/utf8":                             {"AppendRune", "DecodeLastRune", "DecodeLastRuneInString", "DecodeRune", "DecodeRuneInString", "EncodeRune", "FullRune", "FullRuneInString", "RuneCount", "RuneCountInString", "RuneLen", "RuneStart", "Valid", "ValidRune", "ValidString"},
		"unsafe":                                   {"Alignof", "Offsetof", "Sizeof", "String", "StringData"},
	}

	supportedPackages = maps.Keys(packageFunctions)

	autoComplete = append(supportedPackages,
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
	)
)
