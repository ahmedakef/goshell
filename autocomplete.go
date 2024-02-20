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

	lastToken, lastTokenPos := getLastToken(head)
	head = head[:lastTokenPos]

	headSplitted := strings.SplitN(lastToken, ".", 2)
	packageName := headSplitted[0]

	if !contains(supportedPackages, packageName) {
		// this is a not known package, we match to the language keywords
		completions = getPossipleSuggestions(autoComplete, packageName)
		if len(completions) == 0 {
			head += lastToken
		}
		return
	}

	packagePart := packageName + "."
	head = head + packagePart
	function := ""

	allPkgFunctions := packageFunctions[packageName]
	if len(headSplitted) == 2 {
		function = headSplitted[1]
		if function == "" {
			completions = allPkgFunctions
			return
		}
	}

	completions = getPossipleSuggestions(allPkgFunctions, function)
	if len(completions) == 0 {
		head = lastToken
	}
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

func getLastToken(head string) (token string, pos int) {
	headSplitted := strings.Split(head, " ")
	token = headSplitted[len(headSplitted)-1]
	pos = len(head) - len(token)
	return
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

	// populated using scipts/fetcher.go

	packageFunctions = map[string][]string{"archive/tar": {"Format", "Header", "FileInfoHeader", "Reader", "NewReader", "Writer", "NewWriter"},
		"archive/zip":                        {"RegisterCompressor", "RegisterDecompressor", "Compressor", "Decompressor", "File", "FileHeader", "FileInfoHeader", "ReadCloser", "OpenReader", "Reader", "NewReader", "Writer", "NewWriter"},
		"bufio":                              {"ScanBytes", "ScanLines", "ScanRunes", "ScanWords", "ReadWriter", "NewReadWriter", "Reader", "NewReader", "NewReaderSize", "Scanner", "NewScanner", "SplitFunc", "Writer", "NewWriter", "NewWriterSize"},
		"builtin":                            {"append", "cap", "clear", "close", "complex", "copy", "delete", "imag", "len", "make", "max", "min", "new", "panic", "print", "println", "real", "recover", "ComplexType", "FloatType", "IntegerType", "Type", "Type1", "any", "bool", "byte", "comparable", "complex128", "complex64", "error", "float32", "float64", "int", "int16", "int32", "int64", "int8", "rune", "string", "uint", "uint16", "uint32", "uint64", "uint8", "uintptr"},
		"bytes":                              {"Clone", "Compare", "Contains", "ContainsAny", "ContainsFunc", "ContainsRune", "Count", "Cut", "CutPrefix", "CutSuffix", "Equal", "EqualFold", "Fields", "FieldsFunc", "HasPrefix", "HasSuffix", "Index", "IndexAny", "IndexByte", "IndexFunc", "IndexRune", "Join", "LastIndex", "LastIndexAny", "LastIndexByte", "LastIndexFunc", "Map", "Repeat", "Replace", "ReplaceAll", "Runes", "Split", "SplitAfter", "SplitAfterN", "SplitN", "Title", "ToLower", "ToLowerSpecial", "ToTitle", "ToTitleSpecial", "ToUpper", "ToUpperSpecial", "ToValidUTF8", "Trim", "TrimFunc", "TrimLeft", "TrimLeftFunc", "TrimPrefix", "TrimRight", "TrimRightFunc", "TrimSpace", "TrimSuffix", "Buffer", "NewBuffer", "NewBufferString", "Reader", "NewReader"},
		"cmp":                                {"Compare", "Less", "Or", "Ordered"},
		"compress/bzip2":                     {"NewReader", "StructuralError"},
		"compress/flate":                     {"NewReader", "NewReaderDict", "CorruptInputError", "InternalError", "ReadError", "Reader", "Resetter", "WriteError", "Writer", "NewWriter", "NewWriterDict"},
		"compress/gzip":                      {"Header", "Reader", "NewReader", "Writer", "NewWriter", "NewWriterLevel"},
		"compress/lzw":                       {"NewReader", "NewWriter", "Order", "Reader", "Writer"},
		"compress/zlib":                      {"NewReader", "NewReaderDict", "Resetter", "Writer", "NewWriter", "NewWriterLevel", "NewWriterLevelDict"},
		"container/heap":                     {"Fix", "Init", "Pop", "Push", "Remove", "Interface"},
		"container/list":                     {"Element", "List", "New"},
		"container/ring":                     {"Ring", "New"},
		"context":                            {"AfterFunc", "Cause", "WithCancel", "WithCancelCause", "WithDeadline", "WithDeadlineCause", "WithTimeout", "WithTimeoutCause", "CancelCauseFunc", "CancelFunc", "Context", "Background", "TODO", "WithValue", "WithoutCancel"},
		"crypto":                             {"RegisterHash", "Decrypter", "DecrypterOpts", "Hash", "PrivateKey", "PublicKey", "Signer", "SignerOpts"},
		"crypto/aes":                         {"NewCipher", "KeySizeError"},
		"crypto/cipher":                      {"AEAD", "NewGCM", "NewGCMWithNonceSize", "NewGCMWithTagSize", "Block", "BlockMode", "NewCBCDecrypter", "NewCBCEncrypter", "Stream", "NewCFBDecrypter", "NewCFBEncrypter", "NewCTR", "NewOFB", "StreamReader", "StreamWriter"},
		"crypto/des":                         {"NewCipher", "NewTripleDESCipher", "KeySizeError"},
		"crypto/dsa":                         {"GenerateKey", "GenerateParameters", "Sign", "Verify", "ParameterSizes", "Parameters", "PrivateKey", "PublicKey"},
		"crypto/ecdh":                        {"Curve", "P256", "P384", "P521", "X25519", "PrivateKey", "PublicKey"},
		"crypto/ecdsa":                       {"Sign", "SignASN1", "Verify", "VerifyASN1", "PrivateKey", "GenerateKey", "PublicKey"},
		"crypto/ed25519":                     {"GenerateKey", "Sign", "Verify", "VerifyWithOptions", "Options", "PrivateKey", "NewKeyFromSeed", "PublicKey"},
		"crypto/elliptic":                    {"GenerateKey", "Marshal", "MarshalCompressed", "Unmarshal", "UnmarshalCompressed", "Curve", "P224", "P256", "P384", "P521", "CurveParams"},
		"crypto/hmac":                        {"Equal", "New"},
		"crypto/internal/alias":              {"AnyOverlap", "InexactOverlap"},
		"crypto/internal/bigmod":             {"Modulus", "NewModulusFromBig", "Nat", "NewNat"},
		"crypto/internal/boring":             {"DecryptRSANoPadding", "DecryptRSAOAEP", "DecryptRSAPKCS1", "ECDH", "EncryptRSANoPadding", "EncryptRSAOAEP", "EncryptRSAPKCS1", "NewAESCipher", "NewGCMTLS", "NewHMAC", "NewSHA1", "NewSHA224", "NewSHA256", "NewSHA384", "NewSHA512", "SHA1", "SHA224", "SHA256", "SHA384", "SHA512", "SignMarshalECDSA", "SignRSAPKCS1v15", "SignRSAPSS", "Unreachable", "UnreachableExceptTests", "VerifyECDSA", "VerifyRSAPKCS1v15", "VerifyRSAPSS", "BigInt", "GenerateKeyECDSA", "GenerateKeyRSA", "PrivateKeyECDH", "GenerateKeyECDH", "NewPrivateKeyECDH", "PublicKey", "PrivateKeyECDSA", "NewPrivateKeyECDSA", "PrivateKeyRSA", "NewPrivateKeyRSA", "PublicKeyECDH", "NewPublicKeyECDH", "Bytes", "PublicKeyECDSA", "NewPublicKeyECDSA", "PublicKeyRSA", "NewPublicKeyRSA"},
		"crypto/internal/boring/bbig":        {"Dec", "Enc"},
		"crypto/internal/boring/bcache":      {"Cache"},
		"crypto/internal/boring/sig":         {"BoringCrypto", "FIPSOnly", "StandardCrypto"},
		"crypto/internal/edwards25519":       {"Point", "NewGeneratorPoint", "NewIdentityPoint", "Scalar", "NewScalar"},
		"crypto/internal/edwards25519/field": {"Element"},
		"crypto/internal/nistec":             {"P256OrdInverse", "P224Point", "NewP224Point", "P256Point", "NewP256Point", "P384Point", "NewP384Point", "P521Point", "NewP521Point"},
		"crypto/internal/nistec/fiat":        {"P224Element", "P256Element", "P384Element", "P521Element"},
		"crypto/internal/randutil":           {"MaybeReadByte"},
		"crypto/md5":                         {"New", "Sum"},
		"crypto/rand":                        {"Int", "Prime", "Read"},
		"crypto/rc4":                         {"Cipher", "NewCipher", "KeySizeError"},
		"crypto/rsa":                         {"DecryptOAEP", "DecryptPKCS1v15", "DecryptPKCS1v15SessionKey", "EncryptOAEP", "EncryptPKCS1v15", "SignPKCS1v15", "SignPSS", "VerifyPKCS1v15", "VerifyPSS", "CRTValue", "OAEPOptions", "PKCS1v15DecryptOptions", "PSSOptions", "PrecomputedValues", "PrivateKey", "GenerateKey", "GenerateMultiPrimeKey", "PublicKey"},
		"crypto/sha1":                        {"New", "Sum"},
		"crypto/sha256":                      {"New", "New224", "Sum224", "Sum256"},
		"crypto/sha512":                      {"New", "New384", "New512_224", "New512_256", "Sum384", "Sum512", "Sum512_224", "Sum512_256"},
		"crypto/subtle":                      {"ConstantTimeByteEq", "ConstantTimeCompare", "ConstantTimeCopy", "ConstantTimeEq", "ConstantTimeLessOrEq", "ConstantTimeSelect", "XORBytes"},
		"crypto/tls":                         {"CipherSuiteName", "Listen", "NewListener", "VersionName", "AlertError", "Certificate", "LoadX509KeyPair", "X509KeyPair", "CertificateRequestInfo", "CertificateVerificationError", "CipherSuite", "CipherSuites", "InsecureCipherSuites", "ClientAuthType", "ClientHelloInfo", "ClientSessionCache", "NewLRUClientSessionCache", "ClientSessionState", "NewResumptionState", "Config", "Conn", "Client", "Dial", "DialWithDialer", "Server", "ConnectionState", "CurveID", "Dialer", "QUICConfig", "QUICConn", "QUICClient", "QUICServer", "QUICEncryptionLevel", "QUICEvent", "QUICEventKind", "QUICSessionTicketOptions", "RecordHeaderError", "RenegotiationSupport", "SessionState", "ParseSessionState", "SignatureScheme"},
		"crypto/x509":                        {"CreateCertificate", "CreateCertificateRequest", "CreateRevocationList", "DecryptPEMBlock", "EncryptPEMBlock", "IsEncryptedPEMBlock", "MarshalECPrivateKey", "MarshalPKCS1PrivateKey", "MarshalPKCS1PublicKey", "MarshalPKCS8PrivateKey", "MarshalPKIXPublicKey", "ParseCRL", "ParseDERCRL", "ParseECPrivateKey", "ParsePKCS1PrivateKey", "ParsePKCS1PublicKey", "ParsePKCS8PrivateKey", "ParsePKIXPublicKey", "SetFallbackRoots", "CertPool", "NewCertPool", "SystemCertPool", "Certificate", "ParseCertificate", "ParseCertificates", "CertificateInvalidError", "CertificateRequest", "ParseCertificateRequest", "ConstraintViolationError", "Error", "ExtKeyUsage", "HostnameError", "InsecureAlgorithmError", "InvalidReason", "KeyUsage", "OID", "OIDFromInts", "PEMCipher", "PublicKeyAlgorithm", "RevocationList", "ParseRevocationList", "RevocationListEntry", "SignatureAlgorithm", "SystemRootsError", "UnhandledCriticalExtension", "UnknownAuthorityError", "VerifyOptions"},
		"crypto/x509/internal/macos":         {"CFArrayAppendValue", "CFArrayGetCount", "CFDataGetBytePtr", "CFDataGetLength", "CFDataToSlice", "CFEqual", "CFErrorGetCode", "CFNumberGetValue", "CFRelease", "CFStringToString", "ReleaseCFArray", "SecCertificateCopyData", "SecTrustEvaluateWithError", "SecTrustGetCertificateCount", "SecTrustGetResult", "SecTrustSetVerifyDate", "CFRef", "BytesToCFData", "CFArrayCreateMutable", "CFArrayGetValueAtIndex", "CFDateCreate", "CFDictionaryGetValueIfPresent", "CFErrorCopyDescription", "CFStringCreateExternalRepresentation", "SecCertificateCreateWithData", "SecPolicyCreateSSL", "SecTrustCreateWithCertificates", "SecTrustEvaluate", "SecTrustGetCertificateAtIndex", "SecTrustSettingsCopyCertificates", "SecTrustSettingsCopyTrustSettings", "TimeToCFDateRef", "CFString", "StringToCFString", "OSStatus", "SecTrustResultType", "SecTrustSettingsDomain", "SecTrustSettingsResult"},
		"crypto/x509/pkix":                   {"AlgorithmIdentifier", "AttributeTypeAndValue", "AttributeTypeAndValueSET", "CertificateList", "Extension", "Name", "RDNSequence", "RelativeDistinguishedNameSET", "RevokedCertificate", "TBSCertificateList"},
		"database/sql":                       {"Drivers", "Register", "ColumnType", "Conn", "DB", "Open", "OpenDB", "DBStats", "IsolationLevel", "NamedArg", "Named", "Null", "NullBool", "NullByte", "NullFloat64", "NullInt16", "NullInt32", "NullInt64", "NullString", "NullTime", "Out", "RawBytes", "Result", "Row", "Rows", "Scanner", "Stmt", "Tx", "TxOptions"},
		"database/sql/driver":                {"IsScanValue", "IsValue", "ColumnConverter", "Conn", "ConnBeginTx", "ConnPrepareContext", "Connector", "Driver", "DriverContext", "Execer", "ExecerContext", "IsolationLevel", "NamedValue", "NamedValueChecker", "NotNull", "Null", "Pinger", "Queryer", "QueryerContext", "Result", "Rows", "RowsAffected", "LastInsertId", "RowsColumnTypeDatabaseTypeName", "RowsColumnTypeLength", "RowsColumnTypeNullable", "RowsColumnTypePrecisionScale", "RowsColumnTypeScanType", "RowsNextResultSet", "SessionResetter", "Stmt", "StmtExecContext", "StmtQueryContext", "Tx", "TxOptions", "Validator", "Value", "ValueConverter", "Valuer"},
		"debug/buildinfo":                    {"BuildInfo", "Read", "ReadFile"},
		"debug/dwarf":                        {"AddrType", "ArrayType", "Attr", "BasicType", "BoolType", "CharType", "Class", "CommonType", "ComplexType", "Data", "New", "DecodeError", "DotDotDotType", "Entry", "EnumType", "EnumValue", "Field", "FloatType", "FuncType", "IntType", "LineEntry", "LineFile", "LineReader", "LineReaderPos", "Offset", "PtrType", "QualType", "Reader", "StructField", "StructType", "Tag", "Type", "TypedefType", "UcharType", "UintType", "UnspecifiedType", "UnsupportedType", "VoidType"},
		"debug/elf":                          {"R_INFO", "R_INFO32", "R_SYM32", "R_SYM64", "R_TYPE32", "R_TYPE64", "ST_INFO", "Chdr32", "Chdr64", "Class", "CompressionType", "Data", "Dyn32", "Dyn64", "DynFlag", "DynFlag1", "DynTag", "File", "NewFile", "Open", "FileHeader", "FormatError", "Header32", "Header64", "ImportedSymbol", "Machine", "NType", "OSABI", "Prog", "Prog32", "Prog64", "ProgFlag", "ProgHeader", "ProgType", "R_386", "R_390", "R_AARCH64", "R_ALPHA", "R_ARM", "R_LARCH", "R_MIPS", "R_PPC", "R_PPC64", "R_RISCV", "R_SPARC", "R_X86_64", "Rel32", "Rel64", "Rela32", "Rela64", "Section", "Section32", "Section64", "SectionFlag", "SectionHeader", "SectionIndex", "SectionType", "Sym32", "Sym64", "SymBind", "ST_BIND", "SymType", "ST_TYPE", "SymVis", "ST_VISIBILITY", "Symbol", "Type", "Version"},
		"debug/gosym":                        {"DecodingError", "Func", "LineTable", "NewLineTable", "Obj", "Sym", "Table", "NewTable", "UnknownFileError", "UnknownLineError"},
		"debug/macho":                        {"Cpu", "Dylib", "DylibCmd", "Dysymtab", "DysymtabCmd", "FatArch", "FatArchHeader", "FatFile", "NewFatFile", "OpenFat", "File", "NewFile", "Open", "FileHeader", "FormatError", "Load", "LoadBytes", "LoadCmd", "Nlist32", "Nlist64", "Regs386", "RegsAMD64", "Reloc", "RelocTypeARM", "RelocTypeARM64", "RelocTypeGeneric", "RelocTypeX86_64", "Rpath", "RpathCmd", "Section", "Section32", "Section64", "SectionHeader", "Segment", "Segment32", "Segment64", "SegmentHeader", "Symbol", "Symtab", "SymtabCmd", "Thread", "Type"},
		"debug/pe":                           {"COFFSymbol", "COFFSymbolAuxFormat5", "DataDirectory", "File", "NewFile", "Open", "FileHeader", "FormatError", "ImportDirectory", "OptionalHeader32", "OptionalHeader64", "Reloc", "Section", "SectionHeader", "SectionHeader32", "StringTable", "Symbol"},
		"debug/plan9obj":                     {"File", "NewFile", "Open", "FileHeader", "Section", "SectionHeader", "Sym"},
		"embed":                              {"FS"},
		"encoding":                           {"BinaryMarshaler", "BinaryUnmarshaler", "TextMarshaler", "TextUnmarshaler"},
		"encoding/ascii85":                   {"Decode", "Encode", "MaxEncodedLen", "NewDecoder", "NewEncoder", "CorruptInputError"},
		"encoding/asn1":                      {"Marshal", "MarshalWithParams", "Unmarshal", "UnmarshalWithParams", "BitString", "Enumerated", "Flag", "ObjectIdentifier", "RawContent", "RawValue", "StructuralError", "SyntaxError"},
		"encoding/base32":                    {"NewDecoder", "NewEncoder", "CorruptInputError", "Encoding", "NewEncoding"},
		"encoding/base64":                    {"NewDecoder", "NewEncoder", "CorruptInputError", "Encoding", "NewEncoding"},
		"encoding/binary":                    {"AppendUvarint", "AppendVarint", "PutUvarint", "PutVarint", "Read", "ReadUvarint", "ReadVarint", "Size", "Uvarint", "Varint", "Write", "AppendByteOrder", "ByteOrder"},
		"encoding/csv":                       {"ParseError", "Reader", "NewReader", "Writer", "NewWriter"},
		"encoding/gob":                       {"Register", "RegisterName", "CommonType", "Decoder", "NewDecoder", "Encoder", "NewEncoder", "GobDecoder", "GobEncoder"},
		"encoding/hex":                       {"AppendDecode", "AppendEncode", "Decode", "DecodeString", "DecodedLen", "Dump", "Dumper", "Encode", "EncodeToString", "EncodedLen", "NewDecoder", "NewEncoder", "InvalidByteError"},
		"encoding/json":                      {"Compact", "HTMLEscape", "Indent", "Marshal", "MarshalIndent", "Unmarshal", "Valid", "Decoder", "NewDecoder", "Delim", "Encoder", "NewEncoder", "InvalidUTF8Error", "InvalidUnmarshalError", "Marshaler", "MarshalerError", "Number", "RawMessage", "SyntaxError", "Token", "UnmarshalFieldError", "UnmarshalTypeError", "Unmarshaler", "UnsupportedTypeError", "UnsupportedValueError"},
		"encoding/pem":                       {"Encode", "EncodeToMemory", "Block", "Decode"},
		"encoding/xml":                       {"Escape", "EscapeText", "Marshal", "MarshalIndent", "Unmarshal", "Attr", "CharData", "Comment", "Decoder", "NewDecoder", "NewTokenDecoder", "Directive", "Encoder", "NewEncoder", "EndElement", "Marshaler", "MarshalerAttr", "Name", "ProcInst", "StartElement", "SyntaxError", "TagPathError", "Token", "CopyToken", "TokenReader", "UnmarshalError", "Unmarshaler", "UnmarshalerAttr", "UnsupportedTypeError"},
		"errors":                             {"As", "Is", "Join", "New", "Unwrap"},
		"expvar":                             {"Do", "Handler", "Publish", "Float", "NewFloat", "Func", "Int", "NewInt", "KeyValue", "Map", "NewMap", "String", "NewString", "Var", "Get"},
		"flag":                               {"Arg", "Args", "Bool", "BoolFunc", "BoolVar", "Duration", "DurationVar", "Float64", "Float64Var", "Func", "Int", "Int64", "Int64Var", "IntVar", "NArg", "NFlag", "Parse", "Parsed", "PrintDefaults", "Set", "String", "StringVar", "TextVar", "Uint", "Uint64", "Uint64Var", "UintVar", "UnquoteUsage", "Var", "Visit", "VisitAll", "ErrorHandling", "Flag", "Lookup", "FlagSet", "NewFlagSet", "Getter", "Value"},
		"fmt":                                {"Append", "Appendf", "Appendln", "Errorf", "FormatString", "Fprint", "Fprintf", "Fprintln", "Fscan", "Fscanf", "Fscanln", "Print", "Printf", "Println", "Scan", "Scanf", "Scanln", "Sprint", "Sprintf", "Sprintln", "Sscan", "Sscanf", "Sscanln", "Formatter", "GoStringer", "ScanState", "Scanner", "State", "Stringer"},
		"go/ast":                             {"FileExports", "FilterDecl", "FilterFile", "FilterPackage", "Fprint", "Inspect", "IsExported", "IsGenerated", "NotNilFilter", "PackageExports", "Print", "SortImports", "Walk", "ArrayType", "AssignStmt", "BadDecl", "BadExpr", "BadStmt", "BasicLit", "BinaryExpr", "BlockStmt", "BranchStmt", "CallExpr", "CaseClause", "ChanDir", "ChanType", "CommClause", "Comment", "CommentGroup", "CommentMap", "NewCommentMap", "CompositeLit", "Decl", "DeclStmt", "DeferStmt", "Ellipsis", "EmptyStmt", "Expr", "Unparen", "ExprStmt", "Field", "FieldFilter", "FieldList", "File", "MergePackageFiles", "Filter", "ForStmt", "FuncDecl", "FuncLit", "FuncType", "GenDecl", "GoStmt", "Ident", "NewIdent", "IfStmt", "ImportSpec", "Importer", "IncDecStmt", "IndexExpr", "IndexListExpr", "InterfaceType", "KeyValueExpr", "LabeledStmt", "MapType", "MergeMode", "Node", "ObjKind", "Object", "NewObj", "Package", "NewPackage", "ParenExpr", "RangeStmt", "ReturnStmt", "Scope", "NewScope", "SelectStmt", "SelectorExpr", "SendStmt", "SliceExpr", "Spec", "StarExpr", "Stmt", "StructType", "SwitchStmt", "TypeAssertExpr", "TypeSpec", "TypeSwitchStmt", "UnaryExpr", "ValueSpec", "Visitor"},
		"go/build":                           {"ArchChar", "IsLocalImport", "Context", "Directive", "ImportMode", "MultiplePackageError", "NoGoError", "Package", "Import", "ImportDir"},
		"go/build/constraint":                {"GoVersion", "IsGoBuild", "IsPlusBuild", "PlusBuildLines", "AndExpr", "Expr", "Parse", "NotExpr", "OrExpr", "SyntaxError", "TagExpr"},
		"go/constant":                        {"BitLen", "BoolVal", "Bytes", "Compare", "Float32Val", "Float64Val", "Int64Val", "Sign", "StringVal", "Uint64Val", "Val", "Kind", "Value", "BinaryOp", "Denom", "Imag", "Make", "MakeBool", "MakeFloat64", "MakeFromBytes", "MakeFromLiteral", "MakeImag", "MakeInt64", "MakeString", "MakeUint64", "MakeUnknown", "Num", "Real", "Shift", "ToComplex", "ToFloat", "ToInt", "UnaryOp"},
		"go/doc":                             {"IsPredeclared", "Synopsis", "ToHTML", "ToText", "Example", "Examples", "Filter", "Func", "Mode", "Note", "Package", "New", "NewFromFiles", "Type", "Value"},
		"go/doc/comment":                     {"DefaultLookupPackage", "Block", "Code", "Doc", "DocLink", "Heading", "Italic", "Link", "LinkDef", "List", "ListItem", "Paragraph", "Parser", "Plain", "Printer", "Text"},
		"go/format":                          {"Node", "Source"},
		"go/importer":                        {"Default", "For", "ForCompiler", "Lookup"},
		"go/internal/gccgoimporter":          {"GccgoInstallation", "Importer", "GetImporter", "InitData", "PackageInit"},
		"go/internal/gcimporter":             {"FindExportData", "FindPkg", "Import"},
		"go/internal/srcimporter":            {"Importer", "New"},
		"go/internal/typeparams":             {"PackIndexExpr", "IndexExpr", "UnpackIndexExpr"},
		"go/parser":                          {"ParseDir", "ParseExpr", "ParseExprFrom", "ParseFile", "Mode"},
		"go/printer":                         {"Fprint", "CommentedNode", "Config", "Mode"},
		"go/scanner":                         {"PrintError", "Error", "ErrorHandler", "ErrorList", "Mode", "Scanner"},
		"go/token":                           {"IsExported", "IsIdentifier", "IsKeyword", "File", "FileSet", "NewFileSet", "Pos", "Position", "Token", "Lookup"},
		"go/types":                           {"AssertableTo", "AssignableTo", "CheckExpr", "Comparable", "ConvertibleTo", "DefPredeclaredTestFuncs", "ExprString", "Id", "Identical", "IdenticalIgnoreTags", "Implements", "IsInterface", "ObjectString", "Satisfies", "SelectionString", "TypeString", "WriteExpr", "WriteSignature", "WriteType", "Alias", "NewAlias", "ArgumentError", "Array", "NewArray", "Basic", "BasicInfo", "BasicKind", "Builtin", "Chan", "NewChan", "ChanDir", "Checker", "NewChecker", "Config", "Const", "NewConst", "Context", "NewContext", "Error", "Func", "MissingMethod", "NewFunc", "ImportMode", "Importer", "ImporterFrom", "Info", "Initializer", "Instance", "Interface", "NewInterface", "NewInterfaceType", "Label", "NewLabel", "Map", "NewMap", "MethodSet", "NewMethodSet", "Named", "NewNamed", "Nil", "Object", "LookupFieldOrMethod", "Package", "NewPackage", "PkgName", "NewPkgName", "Pointer", "NewPointer", "Qualifier", "RelativeTo", "Scope", "NewScope", "Selection", "SelectionKind", "Signature", "NewSignature", "NewSignatureType", "Sizes", "SizesFor", "Slice", "NewSlice", "StdSizes", "Struct", "NewStruct", "Term", "NewTerm", "Tuple", "NewTuple", "Type", "Default", "Instantiate", "Unalias", "TypeAndValue", "Eval", "TypeList", "TypeName", "NewTypeName", "TypeParam", "NewTypeParam", "TypeParamList", "Union", "NewUnion", "Var", "NewField", "NewParam", "NewVar"},
		"go/version":                         {"Compare", "IsValid", "Lang"},
		"hash":                               {"Hash", "Hash32", "Hash64"},
		"hash/adler32":                       {"Checksum", "New"},
		"hash/crc32":                         {"Checksum", "ChecksumIEEE", "New", "NewIEEE", "Update", "Table", "MakeTable"},
		"hash/crc64":                         {"Checksum", "New", "Update", "Table", "MakeTable"},
		"hash/fnv":                           {"New128", "New128a", "New32", "New32a", "New64", "New64a"},
		"hash/maphash":                       {"Bytes", "String", "Hash", "Seed", "MakeSeed"},
		"html":                               {"EscapeString", "UnescapeString"},
		"html/template":                      {"HTMLEscape", "HTMLEscapeString", "HTMLEscaper", "IsTrue", "JSEscape", "JSEscapeString", "JSEscaper", "URLQueryEscaper", "CSS", "Error", "ErrorCode", "FuncMap", "HTML", "HTMLAttr", "JS", "JSStr", "Srcset", "Template", "Must", "New", "ParseFS", "ParseFiles", "ParseGlob", "URL"},
		"image":                              {"RegisterFormat", "Alpha", "NewAlpha", "Alpha16", "NewAlpha16", "CMYK", "NewCMYK", "Config", "DecodeConfig", "Gray", "NewGray", "Gray16", "NewGray16", "Image", "Decode", "NRGBA", "NewNRGBA", "NRGBA64", "NewNRGBA64", "NYCbCrA", "NewNYCbCrA", "Paletted", "NewPaletted", "PalettedImage", "Point", "Pt", "RGBA", "NewRGBA", "RGBA64", "NewRGBA64", "RGBA64Image", "Rectangle", "Rect", "Uniform", "NewUniform", "YCbCr", "NewYCbCr", "YCbCrSubsampleRatio"},
		"image/color":                        {"CMYKToRGB", "RGBToCMYK", "RGBToYCbCr", "YCbCrToRGB", "Alpha", "Alpha16", "CMYK", "Color", "Gray", "Gray16", "Model", "ModelFunc", "NRGBA", "NRGBA64", "NYCbCrA", "Palette", "RGBA", "RGBA64", "YCbCr"},
		"image/color/palette":                {},
		"image/draw":                         {"Draw", "DrawMask", "Drawer", "Image", "Op", "Quantizer", "RGBA64Image"},
		"image/gif":                          {"Decode", "DecodeConfig", "Encode", "EncodeAll", "GIF", "DecodeAll", "Options"},
		"image/internal/imageutil":           {"DrawYCbCr"},
		"image/jpeg":                         {"Decode", "DecodeConfig", "Encode", "FormatError", "Options", "Reader", "UnsupportedError"},
		"image/png":                          {"Decode", "DecodeConfig", "Encode", "CompressionLevel", "Encoder", "EncoderBuffer", "EncoderBufferPool", "FormatError", "UnsupportedError"},
		"index/suffixarray":                  {"Index", "New"},
		"internal/abi":                       {"CommonSize", "FuncPCABI0", "FuncPCABIInternal", "StructFieldSize", "TFlagOff", "UncommonSize", "UseInterfaceSwitchCache", "ArrayType", "ChanDir", "ChanType", "FuncFlag", "FuncID", "FuncType", "Imethod", "IntArgRegBitmap", "InterfaceSwitch", "InterfaceSwitchCache", "InterfaceSwitchCacheEntry", "InterfaceType", "Kind", "MapType", "Method", "Name", "NewName", "NameOff", "PtrType", "RegArgs", "SliceType", "StructField", "StructType", "TFlag", "TextOff", "Type", "TypeAssert", "TypeAssertCache", "TypeAssertCacheEntry", "TypeOff", "UncommonType"},
		"internal/bisect":                    {"AppendMarker", "CutMarker", "Hash", "Marker", "PrintMarker", "Matcher", "New", "Writer"},
		"internal/buildcfg":                  {"Check", "GOGOARCH", "Getgoextlinkenabled", "ExperimentFlags", "ParseGOEXPERIMENT"},
		"internal/bytealg":                   {"Compare", "Count", "CountString", "Cutover", "Equal", "HashStr", "HashStrRev", "Index", "IndexByte", "IndexByteString", "IndexRabinKarp", "IndexString", "LastIndexByte", "LastIndexByteString", "LastIndexRabinKarp", "MakeNoZero"},
		"internal/cfg":                       {},
		"internal/chacha8rand":               {"Marshal", "Unmarshal", "State"},
		"internal/coverage":                  {"HardCodedPkgID", "Round4", "CounterFileFooter", "CounterFileHeader", "CounterFlavor", "CounterGranularity", "CounterMode", "ParseCounterMode", "CounterSegmentHeader", "CoverableUnit", "FuncDesc", "MetaFileCollection", "MetaFileHeader", "MetaSymbolHeader"},
		"internal/coverage/calloc":           {"BatchCounterAlloc"},
		"internal/coverage/cformat":          {"Formatter", "NewFormatter"},
		"internal/coverage/cmerge":           {"SaturatingAdd", "Merger", "ModeMergePolicy"},
		"internal/coverage/decodecounter":    {"CounterDataReader", "NewCounterDataReader", "FuncPayload"},
		"internal/coverage/decodemeta":       {"CoverageMetaDataDecoder", "NewCoverageMetaDataDecoder", "CoverageMetaFileReader", "NewCoverageMetaFileReader"},
		"internal/coverage/encodecounter":    {"CounterVisitor", "CounterVisitorFn", "CoverageDataWriter", "NewCoverageDataWriter"},
		"internal/coverage/encodemeta":       {"HashFuncDesc", "CoverageMetaDataBuilder", "NewCoverageMetaDataBuilder", "CoverageMetaFileWriter", "NewCoverageMetaFileWriter"},
		"internal/coverage/pods":             {"Pod", "CollectPods", "CollectPodsFromFiles"},
		"internal/coverage/rtcov":            {"CovCounterBlob", "CovMetaBlob"},
		"internal/coverage/slicereader":      {"Reader", "NewReader"},
		"internal/coverage/slicewriter":      {"WriteSeeker"},
		"internal/coverage/stringtab":        {"Reader", "NewReader", "Writer"},
		"internal/coverage/uleb128":          {"AppendUleb128"},
		"internal/cpu":                       {"Initialize", "Name", "CacheLinePad"},
		"internal/dag":                       {"Graph", "Parse"},
		"internal/diff":                      {"Diff"},
		"internal/fmtsort":                   {"SortedMap", "Sort"},
		"internal/fuzz":                      {"CheckCorpus", "CoordinateFuzzing", "ResetCoverage", "RunFuzzWorker", "SnapshotCoverage", "CoordinateFuzzingOpts", "CorpusEntry", "ReadCorpus", "MalformedCorpusError"},
		"internal/goarch":                    {"ArchFamilyType"},
		"internal/godebug":                   {"Setting", "New"},
		"internal/godebugs":                  {"Info", "Lookup"},
		"internal/goexperiment":              {"Flags"},
		"internal/goos":                      {},
		"internal/goroot":                    {"IsStandardPackage"},
		"internal/gover":                     {"CmpInt", "Compare", "DecInt", "IsLang", "IsValid", "Lang", "Max", "Version", "Parse"},
		"internal/goversion":                 {},
		"internal/intern":                    {"Value", "Get", "GetByString"},
		"internal/itoa":                      {"Itoa", "Uitoa", "Uitox"},
		"internal/lazyregexp":                {"Regexp", "New"},
		"internal/lazytemplate":              {"Template", "New"},
		"internal/nettrace":                  {"LookupIPAltResolverKey", "Trace", "TraceKey"},
		"internal/obscuretestdata":           {"DecodeToTempFile", "ReadFile", "Rot13"},
		"internal/oserror":                   {},
		"internal/pkgbits":                   {"Code", "CodeObj", "CodeType", "CodeVal", "Decoder", "Encoder", "Index", "PkgDecoder", "NewPkgDecoder", "PkgEncoder", "NewPkgEncoder", "RelocEnt", "RelocKind", "SyncMarker"},
		"internal/platform":                  {"ASanSupported", "Broken", "BuildModeSupported", "CgoSupported", "DefaultPIE", "ExecutableHasDWARF", "FirstClass", "FuzzInstrumented", "FuzzSupported", "InternalLinkPIESupported", "MSanSupported", "MustLinkExternal", "RaceDetectorSupported", "OSArch"},
		"internal/poll":                      {"CopyFileRange", "DupCloseOnExec", "IsPollDescriptor", "SendFile", "Splice", "DeadlineExceededError", "FD", "String", "SysFile"},
		"internal/profile":                   {"Demangler", "Function", "Label", "Line", "Location", "Mapping", "Profile", "Merge", "Parse", "ParseTracebacks", "Sample", "TagMatch", "ValueType"},
		"internal/race":                      {"Acquire", "Disable", "Enable", "Errors", "Read", "ReadRange", "Release", "ReleaseMerge", "Write", "WriteRange"},
		"internal/reflectlite":               {"Swapper", "Kind", "Type", "TypeOf", "Value", "ValueOf", "ValueError"},
		"internal/safefilepath":              {"FromFS"},
		"internal/saferio":                   {"ReadData", "ReadDataAt", "SliceCap", "SliceCapWithSize"},
		"internal/singleflight":              {"Group", "Result"},
		"internal/syscall/execenv":           {"Default"},
		"internal/syscall/unix":              {"CopyFileRange", "Eaccess", "Fcntl", "Fstatat", "GetRandom", "HasNonblockFlag", "IsNonblock", "KernelVersion", "Openat", "PidFDSendSignal", "RecvfromInet4", "RecvfromInet6", "RecvmsgInet4", "RecvmsgInet6", "SendmsgNInet4", "SendmsgNInet6", "SendtoInet4", "SendtoInet6", "Unlinkat", "GetRandomFlag"},
		"internal/syscall/windows":           {"AdjustTokenPrivileges", "CreateEnvironmentBlock", "CreateEvent", "DestroyEnvironmentBlock", "DuplicateTokenEx", "ErrorLoadingGetTempPath2", "GetACP", "GetAdaptersAddresses", "GetComputerNameEx", "GetConsoleCP", "GetCurrentThread", "GetFileInformationByHandleEx", "GetFinalPathNameByHandle", "GetModuleFileName", "GetProcessMemoryInfo", "GetProfilesDirectory", "GetSystemDirectory", "GetTempPath2", "GetVolumeInformationByHandle", "GetVolumeNameForVolumeMountPoint", "ImpersonateSelf", "LockFileEx", "LookupPrivilegeValue", "Module32First", "Module32Next", "MoveFileEx", "MultiByteToWideChar", "NetShareAdd", "NetShareDel", "NetUserGetLocalGroups", "OpenSCManager", "OpenService", "OpenThreadToken", "ProcessPrng", "QueryServiceStatus", "Rename", "RevertToSelf", "RtlLookupFunctionEntry", "RtlVirtualUnwind", "SetFileInformationByHandle", "SetTokenInformation", "UTF16PtrToString", "UnlockFileEx", "VirtualQuery", "WSARecvMsg", "WSASendMsg", "WSASendtoInet4", "WSASendtoInet6", "WSASocket", "FILE_ATTRIBUTE_TAG_INFO", "FILE_BASIC_INFO", "FILE_FULL_DIR_INFO", "FILE_ID_BOTH_DIR_INFO", "IpAdapterAddresses", "IpAdapterAnycastAddress", "IpAdapterDnsServerAdapter", "IpAdapterMulticastAddress", "IpAdapterPrefix", "IpAdapterUnicastAddress", "LUID", "LUID_AND_ATTRIBUTES", "LocalGroupUserInfo0", "MemoryBasicInformation", "ModuleEntry32", "MountPointReparseBuffer", "PROCESS_MEMORY_COUNTERS", "REPARSE_DATA_BUFFER", "REPARSE_DATA_BUFFER_HEADER", "SERVICE_STATUS", "SHARE_INFO_2", "SID_AND_ATTRIBUTES", "SecurityAttributes", "SocketAddress", "SymbolicLinkReparseBuffer", "TCP_INITIAL_RTO_PARAMETERS", "TOKEN_MANDATORY_LABEL", "TOKEN_PRIVILEGES", "TokenType", "UserInfo4", "WSAMsg"},
		"internal/syscall/windows/registry":  {"DeleteKey", "ExpandString", "Key", "CreateKey", "OpenKey", "KeyInfo"},
		"internal/syscall/windows/sysdll":    {"Add"},
		"internal/sysinfo":                   {"CPUName"},
		"internal/testenv":                   {"Builder", "CPUIsSlow", "CanInternalLink", "CleanCmdEnv", "Command", "CommandContext", "GOROOT", "GoTool", "GoToolPath", "HasCGO", "HasExternalNetwork", "HasGoBuild", "HasGoRun", "HasLink", "HasParallelism", "HasSrc", "HasSymlink", "MustHaveBuildMode", "MustHaveCGO", "MustHaveExec", "MustHaveExecPath", "MustHaveExternalNetwork", "MustHaveGoBuild", "MustHaveGoRun", "MustHaveLink", "MustHaveParallelism", "MustHaveSymlink", "MustInternalLink", "OptimizationOff", "SkipFlaky", "SkipFlakyNet", "SkipIfOptimizationOff", "SkipIfShortAndSlow", "SyscallIsNotSupported", "WriteImportcfg"},
		"internal/testlog":                   {"Getenv", "Open", "PanicOnExit0", "SetLogger", "SetPanicOnExit0", "Stat", "Interface", "Logger"},
		"internal/testpty":                   {"Open", "PtyError"},
		"internal/trace":                     {"GoroutineStats", "IsSystemGoroutine", "MutatorUtilization", "MutatorUtilizationV2", "Print", "PrintEvent", "ReadVersion", "RelatedGoroutines", "RelatedGoroutinesV2", "Event", "Frame", "GDesc", "GExecutionStat", "GoroutineExecStats", "GoroutineSummary", "MMUCurve", "NewMMUCurve", "MutatorUtil", "ParseResult", "Parse", "Summarizer", "NewSummarizer", "Summary", "UserRegionDesc", "UserRegionSummary", "UserTaskSummary", "UtilFlags", "UtilWindow", "Writer", "NewWriter"},
		"internal/trace/traceviewer":         {"BuildProfile", "MMUHandlerFunc", "MainHandler", "SVGProfileHandlerFunc", "StaticHandler", "TraceHandler", "WalkStackFrames", "ArrowEvent", "AsyncSliceEvent", "Emitter", "NewEmitter", "GState", "InstantEvent", "Mode", "MutatorUtilFunc", "ProfileFunc", "ProfileRecord", "Range", "SliceEvent", "ThreadState", "TimeHistogram", "TraceConsumer", "SplittingTraceConsumer", "ViewerDataTraceConsumer", "View", "ViewType"},
		"internal/trace/traceviewer/format":  {"BlockedArg", "Data", "Event", "Frame", "GoroutineCountersArg", "HeapCountersArg", "NameArg", "SortIndexArg", "ThreadCountersArg", "ThreadIDArg"},
		"internal/trace/v2":                  {"Event", "EventKind", "GoID", "GoState", "Label", "Log", "Metric", "ProcID", "ProcState", "Range", "RangeAttribute", "Reader", "NewReader", "Region", "ResourceID", "MakeResourceID", "ResourceKind", "Stack", "StackFrame", "StateTransition", "Task", "TaskID", "ThreadID", "Time", "Value", "ValueKind"},
		"internal/trace/v2/event":            {"Names", "Constraint", "SchedReqs", "Spec", "Type"},
		"internal/trace/v2/event/go122":      {"EventString", "Specs", "GoStatus", "ProcStatus"},
		"internal/trace/v2/internal/testgen/go122": {"Main", "Batch", "Generation", "Seq", "Time", "Trace", "NewTrace"},
		"internal/trace/v2/raw":                    {"Event", "Reader", "NewReader", "TextReader", "NewTextReader", "TextWriter", "NewTextWriter", "Writer", "NewWriter"},
		"internal/trace/v2/testtrace":              {"Expectation", "ExpectSuccess", "ParseExpectation", "ParseFile", "Validator", "NewValidator"},
		"internal/trace/v2/version":                {"WriteHeader", "Version", "ReadHeader"},
		"internal/txtar":                           {"Format", "Archive", "Parse", "ParseFile", "File"},
		"internal/types/errors":                    {"Code"},
		"internal/unsafeheader":                    {"Slice", "String"},
		"internal/xcoff":                           {"Archive", "NewArchive", "OpenArchive", "ArchiveHeader", "AuxCSect32", "AuxCSect64", "AuxFcn32", "AuxFcn64", "AuxFile64", "AuxSect64", "AuxiliaryCSect", "AuxiliaryFcn", "File", "NewFile", "Open", "FileHeader", "FileHeader32", "FileHeader64", "ImportedSymbol", "LoaderHeader32", "LoaderHeader64", "LoaderSymbol32", "LoaderSymbol64", "Member", "MemberHeader", "Reloc", "Reloc32", "Reloc64", "Section", "SectionHeader", "SectionHeader32", "SectionHeader64", "SymEnt32", "SymEnt64", "Symbol"},
		"internal/zstd":                            {"Reader", "NewReader"},
		"io":                                       {"Copy", "CopyBuffer", "CopyN", "Pipe", "ReadAll", "ReadAtLeast", "ReadFull", "WriteString", "ByteReader", "ByteScanner", "ByteWriter", "Closer", "LimitedReader", "OffsetWriter", "NewOffsetWriter", "PipeReader", "PipeWriter", "ReadCloser", "NopCloser", "ReadSeekCloser", "ReadSeeker", "ReadWriteCloser", "ReadWriteSeeker", "ReadWriter", "Reader", "LimitReader", "MultiReader", "TeeReader", "ReaderAt", "ReaderFrom", "RuneReader", "RuneScanner", "SectionReader", "NewSectionReader", "Seeker", "StringWriter", "WriteCloser", "WriteSeeker", "Writer", "MultiWriter", "WriterAt", "WriterTo"},
		"io/fs":                                    {"FormatDirEntry", "FormatFileInfo", "Glob", "ReadFile", "ValidPath", "WalkDir", "DirEntry", "FileInfoToDirEntry", "ReadDir", "FS", "Sub", "File", "FileInfo", "Stat", "FileMode", "GlobFS", "PathError", "ReadDirFS", "ReadDirFile", "ReadFileFS", "StatFS", "SubFS", "WalkDirFunc"},
		"io/ioutil":                                {"NopCloser", "ReadAll", "ReadDir", "ReadFile", "TempDir", "TempFile", "WriteFile"},
		"log":                                      {"Fatal", "Fatalf", "Fatalln", "Flags", "Output", "Panic", "Panicf", "Panicln", "Prefix", "Print", "Printf", "Println", "SetFlags", "SetOutput", "SetPrefix", "Writer", "Logger", "Default", "New"},
		"log/internal":                             {},
		"log/slog":                                 {"Debug", "DebugContext", "Error", "ErrorContext", "Info", "InfoContext", "Log", "LogAttrs", "NewLogLogger", "SetDefault", "Warn", "WarnContext", "Attr", "Any", "Bool", "Duration", "Float64", "Group", "Int", "Int64", "String", "Time", "Uint64", "Handler", "HandlerOptions", "JSONHandler", "NewJSONHandler", "Kind", "Level", "SetLogLoggerLevel", "LevelVar", "Leveler", "LogValuer", "Logger", "Default", "New", "With", "Record", "NewRecord", "Source", "TextHandler", "NewTextHandler", "Value", "AnyValue", "BoolValue", "DurationValue", "Float64Value", "GroupValue", "Int64Value", "IntValue", "StringValue", "TimeValue", "Uint64Value"},
		"log/slog/internal":                        {},
		"log/slog/internal/benchmarks":             {},
		"log/slog/internal/buffer":                 {"Buffer", "New"},
		"log/slog/internal/slogtest":               {"RemoveTime"},
		"log/syslog":                               {"NewLogger", "Priority", "Writer", "Dial", "New"},
		"maps":                                     {"Clone", "Copy", "DeleteFunc", "Equal", "EqualFunc"},
		"math":                                     {"Abs", "Acos", "Acosh", "Asin", "Asinh", "Atan", "Atan2", "Atanh", "Cbrt", "Ceil", "Copysign", "Cos", "Cosh", "Dim", "Erf", "Erfc", "Erfcinv", "Erfinv", "Exp", "Exp2", "Expm1", "FMA", "Float32bits", "Float32frombits", "Float64bits", "Float64frombits", "Floor", "Frexp", "Gamma", "Hypot", "Ilogb", "Inf", "IsInf", "IsNaN", "J0", "J1", "Jn", "Ldexp", "Lgamma", "Log", "Log10", "Log1p", "Log2", "Logb", "Max", "Min", "Mod", "Modf", "NaN", "Nextafter", "Nextafter32", "Pow", "Pow10", "Remainder", "Round", "RoundToEven", "Signbit", "Sin", "Sincos", "Sinh", "Sqrt", "Tan", "Tanh", "Trunc", "Y0", "Y1", "Yn"},
		"math/big":                                 {"Jacobi", "Accuracy", "ErrNaN", "Float", "NewFloat", "ParseFloat", "Int", "NewInt", "Rat", "NewRat", "RoundingMode", "Word"},
		"math/bits":                                {"Add", "Add32", "Add64", "Div", "Div32", "Div64", "LeadingZeros", "LeadingZeros16", "LeadingZeros32", "LeadingZeros64", "LeadingZeros8", "Len", "Len16", "Len32", "Len64", "Len8", "Mul", "Mul32", "Mul64", "OnesCount", "OnesCount16", "OnesCount32", "OnesCount64", "OnesCount8", "Rem", "Rem32", "Rem64", "Reverse", "Reverse16", "Reverse32", "Reverse64", "Reverse8", "ReverseBytes", "ReverseBytes16", "ReverseBytes32", "ReverseBytes64", "RotateLeft", "RotateLeft16", "RotateLeft32", "RotateLeft64", "RotateLeft8", "Sub", "Sub32", "Sub64", "TrailingZeros", "TrailingZeros16", "TrailingZeros32", "TrailingZeros64", "TrailingZeros8"},
		"math/cmplx":                               {"Abs", "Acos", "Acosh", "Asin", "Asinh", "Atan", "Atanh", "Conj", "Cos", "Cosh", "Cot", "Exp", "Inf", "IsInf", "IsNaN", "Log", "Log10", "NaN", "Phase", "Polar", "Pow", "Rect", "Sin", "Sinh", "Sqrt", "Tan", "Tanh"},
		"math/rand":                                {"ExpFloat64", "Float32", "Float64", "Int", "Int31", "Int31n", "Int63", "Int63n", "Intn", "NormFloat64", "Perm", "Read", "Seed", "Shuffle", "Uint32", "Uint64", "Rand", "New", "Source", "NewSource", "Source64", "Zipf", "NewZipf"},
		"math/rand/v2":                             {"ExpFloat64", "Float32", "Float64", "Int", "Int32", "Int32N", "Int64", "Int64N", "IntN", "N", "NormFloat64", "Perm", "Shuffle", "Uint32", "Uint32N", "Uint64", "Uint64N", "UintN", "ChaCha8", "NewChaCha8", "PCG", "NewPCG", "Rand", "New", "Source", "Zipf", "NewZipf"},
		"mime":                                     {"AddExtensionType", "ExtensionsByType", "FormatMediaType", "ParseMediaType", "TypeByExtension", "WordDecoder", "WordEncoder"},
		"mime/multipart":                           {"File", "FileHeader", "Form", "Part", "Reader", "NewReader", "Writer", "NewWriter"},
		"mime/quotedprintable":                     {"Reader", "NewReader", "Writer", "NewWriter"},
		"net":                                      {"JoinHostPort", "LookupAddr", "LookupCNAME", "LookupHost", "LookupPort", "LookupTXT", "ParseCIDR", "Pipe", "SplitHostPort", "Addr", "InterfaceAddrs", "AddrError", "Buffers", "Conn", "Dial", "DialTimeout", "FileConn", "DNSConfigError", "DNSError", "Dialer", "Error", "Flags", "HardwareAddr", "ParseMAC", "IP", "IPv4", "LookupIP", "ParseIP", "IPAddr", "ResolveIPAddr", "IPConn", "DialIP", "ListenIP", "IPMask", "CIDRMask", "IPv4Mask", "IPNet", "Interface", "InterfaceByIndex", "InterfaceByName", "Interfaces", "InvalidAddrError", "ListenConfig", "Listener", "FileListener", "Listen", "MX", "LookupMX", "NS", "LookupNS", "OpError", "PacketConn", "FilePacketConn", "ListenPacket", "ParseError", "Resolver", "SRV", "LookupSRV", "TCPAddr", "ResolveTCPAddr", "TCPAddrFromAddrPort", "TCPConn", "DialTCP", "TCPListener", "ListenTCP", "UDPAddr", "ResolveUDPAddr", "UDPAddrFromAddrPort", "UDPConn", "DialUDP", "ListenMulticastUDP", "ListenUDP", "UnixAddr", "ResolveUnixAddr", "UnixConn", "DialUnix", "ListenUnixgram", "UnixListener", "ListenUnix", "UnknownNetworkError"},
		"net/http":                                 {"CanonicalHeaderKey", "DetectContentType", "Error", "Handle", "HandleFunc", "ListenAndServe", "ListenAndServeTLS", "MaxBytesReader", "NotFound", "ParseHTTPVersion", "ParseTime", "ProxyFromEnvironment", "ProxyURL", "Redirect", "Serve", "ServeContent", "ServeFile", "ServeFileFS", "ServeTLS", "SetCookie", "StatusText", "Client", "CloseNotifier", "ConnState", "Cookie", "CookieJar", "Dir", "File", "FileSystem", "FS", "Flusher", "Handler", "AllowQuerySemicolons", "FileServer", "FileServerFS", "MaxBytesHandler", "NotFoundHandler", "RedirectHandler", "StripPrefix", "TimeoutHandler", "HandlerFunc", "Header", "Hijacker", "MaxBytesError", "ProtocolError", "PushOptions", "Pusher", "Request", "NewRequest", "NewRequestWithContext", "ReadRequest", "Response", "Get", "Head", "Post", "PostForm", "ReadResponse", "ResponseController", "NewResponseController", "ResponseWriter", "RoundTripper", "NewFileTransport", "NewFileTransportFS", "SameSite", "ServeMux", "NewServeMux", "Server", "Transport"},
		"net/http/cgi":                             {"Request", "RequestFromMap", "Serve", "Handler"},
		"net/http/cookiejar":                       {"Jar", "New", "Options", "PublicSuffixList"},
		"net/http/fcgi":                            {"ProcessEnv", "Serve"},
		"net/http/httptest":                        {"NewRequest", "ResponseRecorder", "NewRecorder", "Server", "NewServer", "NewTLSServer", "NewUnstartedServer"},
		"net/http/httptrace":                       {"WithClientTrace", "ClientTrace", "ContextClientTrace", "DNSDoneInfo", "DNSStartInfo", "GotConnInfo", "WroteRequestInfo"},
		"net/http/httputil":                        {"DumpRequest", "DumpRequestOut", "DumpResponse", "NewChunkedReader", "NewChunkedWriter", "BufferPool", "ClientConn", "NewClientConn", "NewProxyClientConn", "ProxyRequest", "ReverseProxy", "NewSingleHostReverseProxy", "ServerConn", "NewServerConn"},
		"net/http/internal":                        {"NewChunkedReader", "NewChunkedWriter", "FlushAfterChunkWriter"},
		"net/http/internal/ascii":                  {"EqualFold", "Is", "IsPrint", "ToLower"},
		"net/http/internal/testcert":               {},
		"net/http/pprof":                           {"Cmdline", "Handler", "Index", "Profile", "Symbol", "Trace"},
		"net/internal/socktest":                    {"AfterFilter", "Cookie", "Filter", "FilterType", "Sockets", "Stat", "Status", "Switch"},
		"net/mail":                                 {"ParseDate", "Address", "ParseAddress", "ParseAddressList", "AddressParser", "Header", "Message", "ReadMessage"},
		"net/netip":                                {"Addr", "AddrFrom16", "AddrFrom4", "AddrFromSlice", "IPv4Unspecified", "IPv6LinkLocalAllNodes", "IPv6LinkLocalAllRouters", "IPv6Loopback", "IPv6Unspecified", "MustParseAddr", "ParseAddr", "AddrPort", "AddrPortFrom", "MustParseAddrPort", "ParseAddrPort", "Prefix", "MustParsePrefix", "ParsePrefix", "PrefixFrom"},
		"net/rpc":                                  {"Accept", "HandleHTTP", "Register", "RegisterName", "ServeCodec", "ServeConn", "ServeRequest", "Call", "Client", "Dial", "DialHTTP", "DialHTTPPath", "NewClient", "NewClientWithCodec", "ClientCodec", "Request", "Response", "Server", "NewServer", "ServerCodec", "ServerError"},
		"net/rpc/jsonrpc":                          {"Dial", "NewClient", "NewClientCodec", "NewServerCodec", "ServeConn"},
		"net/smtp":                                 {"SendMail", "Auth", "CRAMMD5Auth", "PlainAuth", "Client", "Dial", "NewClient", "ServerInfo"},
		"net/textproto":                            {"CanonicalMIMEHeaderKey", "TrimBytes", "TrimString", "Conn", "Dial", "NewConn", "Error", "MIMEHeader", "Pipeline", "ProtocolError", "Reader", "NewReader", "Writer", "NewWriter"},
		"net/url":                                  {"JoinPath", "PathEscape", "PathUnescape", "QueryEscape", "QueryUnescape", "Error", "EscapeError", "InvalidHostError", "URL", "Parse", "ParseRequestURI", "Userinfo", "User", "UserPassword", "Values", "ParseQuery"},
		"os":                                       {"Chdir", "Chmod", "Chown", "Chtimes", "Clearenv", "DirFS", "Environ", "Executable", "Exit", "Expand", "ExpandEnv", "Getegid", "Getenv", "Geteuid", "Getgid", "Getgroups", "Getpagesize", "Getpid", "Getppid", "Getuid", "Getwd", "Hostname", "IsExist", "IsNotExist", "IsPathSeparator", "IsPermission", "IsTimeout", "Lchown", "Link", "LookupEnv", "Mkdir", "MkdirAll", "MkdirTemp", "NewSyscallError", "Pipe", "ReadFile", "Readlink", "Remove", "RemoveAll", "Rename", "SameFile", "Setenv", "Symlink", "TempDir", "Truncate", "Unsetenv", "UserCacheDir", "UserConfigDir", "UserHomeDir", "WriteFile", "DirEntry", "ReadDir", "File", "Create", "CreateTemp", "NewFile", "Open", "OpenFile", "FileInfo", "Lstat", "Stat", "FileMode", "LinkError", "PathError", "ProcAttr", "Process", "FindProcess", "StartProcess", "ProcessState", "Signal", "SyscallError"},
		"os/exec":                                  {"LookPath", "Cmd", "Command", "CommandContext", "Error", "ExitError"},
		"os/exec/internal/fdtest":                  {"Exists"},
		"os/signal":                                {"Ignore", "Ignored", "Notify", "NotifyContext", "Reset", "Stop"},
		"os/user":                                  {"Group", "LookupGroup", "LookupGroupId", "UnknownGroupError", "UnknownGroupIdError", "UnknownUserError", "UnknownUserIdError", "User", "Current", "Lookup", "LookupId"},
		"path":                                     {"Base", "Clean", "Dir", "Ext", "IsAbs", "Join", "Match", "Split"},
		"path/filepath":                            {"Abs", "Base", "Clean", "Dir", "EvalSymlinks", "Ext", "FromSlash", "Glob", "HasPrefix", "IsAbs", "IsLocal", "Join", "Match", "Rel", "Split", "SplitList", "ToSlash", "VolumeName", "Walk", "WalkDir", "WalkFunc"},
		"plugin":                                   {"Plugin", "Open", "Symbol"},
		"reflect":                                  {"Copy", "DeepEqual", "Swapper", "ChanDir", "Kind", "MapIter", "Method", "SelectCase", "SelectDir", "SliceHeader", "StringHeader", "StructField", "VisibleFields", "StructTag", "Type", "ArrayOf", "ChanOf", "FuncOf", "MapOf", "PointerTo", "PtrTo", "SliceOf", "StructOf", "TypeFor", "TypeOf", "Value", "Append", "AppendSlice", "Indirect", "MakeChan", "MakeFunc", "MakeMap", "MakeMapWithSize", "MakeSlice", "New", "NewAt", "Select", "ValueOf", "Zero", "ValueError"},
		"reflect/internal/example1":                {"MyStruct"},
		"reflect/internal/example2":                {"MyStruct"},
		"regexp":                                   {"Match", "MatchReader", "MatchString", "QuoteMeta", "Regexp", "Compile", "CompilePOSIX", "MustCompile", "MustCompilePOSIX"},
		"regexp/syntax":                            {"IsWordChar", "EmptyOp", "EmptyOpContext", "Error", "ErrorCode", "Flags", "Inst", "InstOp", "Op", "Prog", "Compile", "Regexp", "Parse"},
		"runtime":                                  {"BlockProfile", "Breakpoint", "CPUProfile", "Caller", "Callers", "GC", "GOMAXPROCS", "GOROOT", "Goexit", "GoroutineProfile", "Gosched", "KeepAlive", "LockOSThread", "MemProfile", "MutexProfile", "NumCPU", "NumCgoCall", "NumGoroutine", "ReadMemStats", "ReadTrace", "SetBlockProfileRate", "SetCPUProfileRate", "SetCgoTraceback", "SetFinalizer", "SetMutexProfileFraction", "Stack", "StartTrace", "StopTrace", "ThreadCreateProfile", "UnlockOSThread", "Version", "BlockProfileRecord", "Error", "Frame", "Frames", "CallersFrames", "Func", "FuncForPC", "MemProfileRecord", "MemStats", "PanicNilError", "RuntimeError", "Pinner", "StackRecord", "TypeAssertionError"},
		"runtime/cgo":                              {"Handle", "NewHandle", "Incomplete"},
		"runtime/coverage":                         {"ClearCounters", "WriteCounters", "WriteCountersDir", "WriteMeta", "WriteMetaDir"},
		"runtime/debug":                            {"FreeOSMemory", "PrintStack", "ReadGCStats", "SetGCPercent", "SetMaxStack", "SetMaxThreads", "SetMemoryLimit", "SetPanicOnFault", "SetTraceback", "Stack", "WriteHeapDump", "BuildInfo", "ParseBuildInfo", "ReadBuildInfo", "BuildSetting", "GCStats", "Module"},
		"runtime/internal/atomic":                  {"And", "And32", "And64", "And8", "Anduintptr", "Cas", "Cas64", "CasRel", "Casint32", "Casint64", "Casp1", "Casuintptr", "Load", "Load64", "Load8", "LoadAcq", "LoadAcq64", "LoadAcquintptr", "Loadint32", "Loadint64", "Loadp", "Loaduint", "Loaduintptr", "Or", "Or32", "Or64", "Or8", "Oruintptr", "Store", "Store64", "Store8", "StoreRel", "StoreRel64", "StoreReluintptr", "Storeint32", "Storeint64", "StorepNoWB", "Storeuintptr", "Xadd", "Xadd64", "Xaddint32", "Xaddint64", "Xadduintptr", "Xchg", "Xchg64", "Xchgint32", "Xchgint64", "Xchguintptr", "Bool", "Float64", "Int32", "Int64", "Pointer", "Uint32", "Uint64", "Uint8", "Uintptr", "UnsafePointer"},
		"runtime/internal/math":                    {"Add64", "Mul64", "MulUintptr"},
		"runtime/internal/startlinetest":           {"AsmFunc"},
		"runtime/internal/sys":                     {"Bswap32", "Bswap64", "LeadingZeros64", "LeadingZeros8", "Len64", "Len8", "OnesCount64", "Prefetch", "PrefetchStreamed", "TrailingZeros32", "TrailingZeros64", "TrailingZeros8", "NotInHeap"},
		"runtime/internal/syscall":                 {"EpollCreate1", "EpollCtl", "EpollWait", "Syscall6", "EpollEvent"},
		"runtime/metrics":                          {"Read", "Description", "All", "Float64Histogram", "Sample", "Value", "ValueKind"},
		"runtime/pprof":                            {"Do", "ForLabels", "Label", "SetGoroutineLabels", "StartCPUProfile", "StopCPUProfile", "WithLabels", "WriteHeapProfile", "LabelSet", "Labels", "Profile", "Lookup", "NewProfile", "Profiles"},
		"runtime/race":                             {},
		"runtime/race/internal/amd64v1":            {},
		"runtime/trace":                            {"IsEnabled", "Log", "Logf", "Start", "Stop", "WithRegion", "Region", "StartRegion", "Task", "NewTask"},
		"slices":                                   {"BinarySearch", "BinarySearchFunc", "Clip", "Clone", "Compact", "CompactFunc", "Compare", "CompareFunc", "Concat", "Contains", "ContainsFunc", "Delete", "DeleteFunc", "Equal", "EqualFunc", "Grow", "Index", "IndexFunc", "Insert", "IsSorted", "IsSortedFunc", "Max", "MaxFunc", "Min", "MinFunc", "Replace", "Reverse", "Sort", "SortFunc", "SortStableFunc"},
		"sort":                                     {"Find", "Float64s", "Float64sAreSorted", "Ints", "IntsAreSorted", "IsSorted", "Search", "SearchFloat64s", "SearchInts", "SearchStrings", "Slice", "SliceIsSorted", "SliceStable", "Sort", "Stable", "Strings", "StringsAreSorted", "Float64Slice", "IntSlice", "Interface", "Reverse", "StringSlice"},
		"strconv":                                  {"AppendBool", "AppendFloat", "AppendInt", "AppendQuote", "AppendQuoteRune", "AppendQuoteRuneToASCII", "AppendQuoteRuneToGraphic", "AppendQuoteToASCII", "AppendQuoteToGraphic", "AppendUint", "Atoi", "CanBackquote", "FormatBool", "FormatComplex", "FormatFloat", "FormatInt", "FormatUint", "IsGraphic", "IsPrint", "Itoa", "ParseBool", "ParseComplex", "ParseFloat", "ParseInt", "ParseUint", "Quote", "QuoteRune", "QuoteRuneToASCII", "QuoteRuneToGraphic", "QuoteToASCII", "QuoteToGraphic", "QuotedPrefix", "Unquote", "UnquoteChar", "NumError"},
		"strings":                                  {"Clone", "Compare", "Contains", "ContainsAny", "ContainsFunc", "ContainsRune", "Count", "Cut", "CutPrefix", "CutSuffix", "EqualFold", "Fields", "FieldsFunc", "HasPrefix", "HasSuffix", "Index", "IndexAny", "IndexByte", "IndexFunc", "IndexRune", "Join", "LastIndex", "LastIndexAny", "LastIndexByte", "LastIndexFunc", "Map", "Repeat", "Replace", "ReplaceAll", "Split", "SplitAfter", "SplitAfterN", "SplitN", "Title", "ToLower", "ToLowerSpecial", "ToTitle", "ToTitleSpecial", "ToUpper", "ToUpperSpecial", "ToValidUTF8", "Trim", "TrimFunc", "TrimLeft", "TrimLeftFunc", "TrimPrefix", "TrimRight", "TrimRightFunc", "TrimSpace", "TrimSuffix", "Builder", "Reader", "NewReader", "Replacer", "NewReplacer"},
		"sync":                                     {"OnceFunc", "OnceValue", "OnceValues", "Cond", "NewCond", "Locker", "Map", "Mutex", "Once", "Pool", "RWMutex", "WaitGroup"},
		"sync/atomic":                              {"AddInt32", "AddInt64", "AddUint32", "AddUint64", "AddUintptr", "CompareAndSwapInt32", "CompareAndSwapInt64", "CompareAndSwapPointer", "CompareAndSwapUint32", "CompareAndSwapUint64", "CompareAndSwapUintptr", "LoadInt32", "LoadInt64", "LoadPointer", "LoadUint32", "LoadUint64", "LoadUintptr", "StoreInt32", "StoreInt64", "StorePointer", "StoreUint32", "StoreUint64", "StoreUintptr", "SwapInt32", "SwapInt64", "SwapPointer", "SwapUint32", "SwapUint64", "SwapUintptr", "Bool", "Int32", "Int64", "Pointer", "Uint32", "Uint64", "Uintptr", "Value"},
		"syscall":                                  {"Access", "Acct", "Adjtimex", "AttachLsf", "Bind", "BindToDevice", "BytePtrFromString", "ByteSliceFromString", "Chdir", "Chmod", "Chown", "Chroot", "Clearenv", "Close", "CloseOnExec", "CmsgLen", "CmsgSpace", "Connect", "Creat", "DetachLsf", "Dup", "Dup2", "Dup3", "Environ", "EpollCreate", "EpollCreate1", "EpollCtl", "EpollWait", "Exec", "Exit", "Faccessat", "Fallocate", "Fchdir", "Fchmod", "Fchmodat", "Fchown", "Fchownat", "FcntlFlock", "Fdatasync", "Flock", "ForkExec", "Fstat", "Fstatfs", "Fsync", "Ftruncate", "Futimes", "Futimesat", "Getcwd", "Getdents", "Getegid", "Getenv", "Geteuid", "Getgid", "Getgroups", "Getpagesize", "Getpgid", "Getpgrp", "Getpid", "Getppid", "Getpriority", "Getrlimit", "Getrusage", "GetsockoptInet4Addr", "GetsockoptInt", "Gettid", "Gettimeofday", "Getuid", "Getwd", "Getxattr", "InotifyAddWatch", "InotifyInit", "InotifyInit1", "InotifyRmWatch", "Ioperm", "Iopl", "Kill", "Klogctl", "Lchown", "Link", "Listen", "Listxattr", "LsfSocket", "Lstat", "Madvise", "Mkdir", "Mkdirat", "Mkfifo", "Mknod", "Mknodat", "Mlock", "Mlockall", "Mmap", "Mount", "Mprotect", "Munlock", "Munlockall", "Munmap", "Nanosleep", "NetlinkRIB", "Open", "Openat", "ParseDirent", "ParseUnixRights", "Pause", "Pipe", "Pipe2", "PivotRoot", "Pread", "PtraceAttach", "PtraceCont", "PtraceDetach", "PtraceGetEventMsg", "PtraceGetRegs", "PtracePeekData", "PtracePeekText", "PtracePokeData", "PtracePokeText", "PtraceSetOptions", "PtraceSetRegs", "PtraceSingleStep", "PtraceSyscall", "Pwrite", "Read", "ReadDirent", "Readlink", "Reboot", "Removexattr", "Rename", "Renameat", "Rmdir", "Seek", "Select", "Sendfile", "Sendmsg", "SendmsgN", "Sendto", "SetLsfPromisc", "SetNonblock", "Setdomainname", "Setegid", "Setenv", "Seteuid", "Setfsgid", "Setfsuid", "Setgid", "Setgroups", "Sethostname", "Setpgid", "Setpriority", "Setregid", "Setresgid", "Setresuid", "Setreuid", "Setrlimit", "Setsid", "SetsockoptByte", "SetsockoptICMPv6Filter", "SetsockoptIPMreq", "SetsockoptIPMreqn", "SetsockoptIPv6Mreq", "SetsockoptInet4Addr", "SetsockoptInt", "SetsockoptLinger", "SetsockoptString", "SetsockoptTimeval", "Settimeofday", "Setuid", "Setxattr", "Shutdown", "SlicePtrFromStrings", "Socket", "Socketpair", "Splice", "StartProcess", "Stat", "Statfs", "StringBytePtr", "StringByteSlice", "StringSlicePtr", "Symlink", "Sync", "SyncFileRange", "Sysinfo", "Tee", "Tgkill", "Times", "TimespecToNsec", "TimevalToNsec", "Truncate", "Umask", "Uname", "UnixCredentials", "UnixRights", "Unlink", "Unlinkat", "Unmount", "Unsetenv", "Unshare", "Ustat", "Utime", "Utimes", "UtimesNano", "Wait4", "Write", "Cmsghdr", "Conn", "Credential", "Dirent", "EpollEvent", "Errno", "AllThreadsSyscall", "AllThreadsSyscall6", "RawSyscall", "RawSyscall6", "Syscall", "Syscall6", "FdSet", "Flock_t", "Fsid", "ICMPv6Filter", "GetsockoptICMPv6Filter", "IPMreq", "GetsockoptIPMreq", "IPMreqn", "GetsockoptIPMreqn", "IPv6MTUInfo", "GetsockoptIPv6MTUInfo", "IPv6Mreq", "GetsockoptIPv6Mreq", "IfAddrmsg", "IfInfomsg", "Inet4Pktinfo", "Inet6Pktinfo", "InotifyEvent", "Iovec", "Linger", "Msghdr", "NetlinkMessage", "ParseNetlinkMessage", "NetlinkRouteAttr", "ParseNetlinkRouteAttr", "NetlinkRouteRequest", "NlAttr", "NlMsgerr", "NlMsghdr", "ProcAttr", "PtraceRegs", "RawConn", "RawSockaddr", "RawSockaddrAny", "RawSockaddrInet4", "RawSockaddrInet6", "RawSockaddrLinklayer", "RawSockaddrNetlink", "RawSockaddrUnix", "Rlimit", "RtAttr", "RtGenmsg", "RtMsg", "RtNexthop", "Rusage", "Signal", "SockFilter", "LsfJump", "LsfStmt", "SockFprog", "Sockaddr", "Accept", "Accept4", "Getpeername", "Getsockname", "Recvfrom", "Recvmsg", "SockaddrInet4", "SockaddrInet6", "SockaddrLinklayer", "SockaddrNetlink", "SockaddrUnix", "SocketControlMessage", "ParseSocketControlMessage", "Stat_t", "Statfs_t", "SysProcAttr", "SysProcIDMap", "Sysinfo_t", "TCPInfo", "Termios", "Time_t", "Time", "Timespec", "NsecToTimespec", "Timeval", "NsecToTimeval", "Timex", "Tms", "Ucred", "GetsockoptUcred", "ParseUnixCredentials", "Ustat_t", "Utimbuf", "Utsname", "WaitStatus"},
		"syscall/js":                               {"CopyBytesToGo", "CopyBytesToJS", "Error", "Func", "FuncOf", "Type", "Value", "Global", "Null", "Undefined", "ValueOf", "ValueError"},
		"testing":                                  {"AllocsPerRun", "CoverMode", "Coverage", "Init", "Main", "RegisterCover", "RunBenchmarks", "RunExamples", "RunTests", "Short", "Testing", "Verbose", "B", "BenchmarkResult", "Benchmark", "Cover", "CoverBlock", "F", "InternalBenchmark", "InternalExample", "InternalFuzzTarget", "InternalTest", "M", "MainStart", "PB", "T", "TB"},
		"testing/fstest":                           {"TestFS", "MapFS", "MapFile"},
		"testing/internal/testdeps":                {"TestDeps", "CheckCorpus", "CoordinateFuzzing", "ImportPath", "MatchString", "ReadCorpus", "ResetCoverage", "RunFuzzWorker", "SetPanicOnExit0", "SnapshotCoverage", "StartCPUProfile", "StartTestLog", "StopCPUProfile", "StopTestLog", "WriteProfileTo"},
		"testing/iotest":                           {"DataErrReader", "ErrReader", "HalfReader", "NewReadLogger", "NewWriteLogger", "OneByteReader", "TestReader", "TimeoutReader", "TruncateWriter"},
		"testing/quick":                            {"Check", "CheckEqual", "Value", "CheckEqualError", "CheckError", "Config", "Generator", "SetupError"},
		"testing/slogtest":                         {"Run", "TestHandler"},
		"text/scanner":                             {"TokenString", "Position", "Scanner"},
		"text/tabwriter":                           {"Writer", "NewWriter"},
		"text/template":                            {"HTMLEscape", "HTMLEscapeString", "HTMLEscaper", "IsTrue", "JSEscape", "JSEscapeString", "JSEscaper", "URLQueryEscaper", "ExecError", "FuncMap", "Template", "Must", "New", "ParseFS", "ParseFiles", "ParseGlob"},
		"text/template/parse":                      {"IsEmptyTree", "Parse", "ActionNode", "BoolNode", "BranchNode", "BreakNode", "ChainNode", "CommandNode", "CommentNode", "ContinueNode", "DotNode", "FieldNode", "IdentifierNode", "NewIdentifier", "IfNode", "ListNode", "Mode", "NilNode", "Node", "NodeType", "NumberNode", "PipeNode", "Pos", "RangeNode", "StringNode", "TemplateNode", "TextNode", "Tree", "New", "VariableNode", "WithNode"},
		"time":                                     {"After", "Sleep", "Tick", "Duration", "ParseDuration", "Since", "Until", "Location", "FixedZone", "LoadLocation", "LoadLocationFromTZData", "Month", "ParseError", "Ticker", "NewTicker", "Time", "Date", "Now", "Parse", "ParseInLocation", "Unix", "UnixMicro", "UnixMilli", "Timer", "AfterFunc", "NewTimer", "Weekday"},
		"time/tzdata":                              {},
		"unicode":                                  {"In", "Is", "IsControl", "IsDigit", "IsGraphic", "IsLetter", "IsLower", "IsMark", "IsNumber", "IsOneOf", "IsPrint", "IsPunct", "IsSpace", "IsSymbol", "IsTitle", "IsUpper", "SimpleFold", "To", "ToLower", "ToTitle", "ToUpper", "CaseRange", "Range16", "Range32", "RangeTable", "SpecialCase"},
		"unicode/utf16":                            {"AppendRune", "Decode", "DecodeRune", "Encode", "EncodeRune", "IsSurrogate"},
		"unicode/utf8":                             {"AppendRune", "DecodeLastRune", "DecodeLastRuneInString", "DecodeRune", "DecodeRuneInString", "EncodeRune", "FullRune", "FullRuneInString", "RuneCount", "RuneCountInString", "RuneLen", "RuneStart", "Valid", "ValidRune", "ValidString"},
		"unsafe":                                   {"Alignof", "Offsetof", "Sizeof", "String", "StringData", "ArbitraryType", "Slice", "SliceData", "IntegerType", "Pointer", "Add"},
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
