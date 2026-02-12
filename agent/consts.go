package main

const (
	//TODO: creation flags
	//TODO: memory protection constants
	//TODO: thread/process access constants
	//TODO: integrity level enums
	MAX_PATH                  = 260 // MAX_PATH from windows.h
	ALERT_ICON_PATH           = "./rsrc/icon.png"
	NOTIFICATION_PREFIX       = "genesis-helper://"
	DEFAULT_RULE_DIR          = "./rules"
	DEFAULT_PATTERN_FILENAME  = "apipatterns.json"
	DEFAULT_FUNCLIST_FILENAME = "malapi.json"
	API_PATTERN_EXTENSION     = ".pattern"
	YARA_FILE_EXTENSION       = ".yara"
	MAX_INDIVIDUAL_FN_SCORE   = 20 // static analysis
	MAX_PATTERN_SCORE         = 60 // static analysis
	LOW_FN_DEFAULT_SCORE      = 1
	MEDIUM_FN_DEFAULT_SCORE   = 3
	HIGH_FN_DEFAULT_SCORE     = 6
	MAX_PROCESS_SCORE         = 100
	MAX_STATIC_SCORE          = 100

	SCORE_STATIC_ALERT_THRESHOLD = 60
	SCORE_STATIC_FINAL_THRESHOLD = 90
	SCORE_RANSOM_ALERT_THRESHOLD = 50
	SCORE_RANSOM_FINAL_THRESHOLD = 80
	SCORE_TOTAL_ALERT_THRESHOLD  = 50
	SCORE_TOTAL_FINAL_THRESHOLD  = 80

	MEMORYSCAN_INTERVAL         = 30  //sec
	THREADSCAN_INTERVAL         = 30  //sec
	HANDLESCAN_INTERVAL         = 30  // sec
	HEARTBEAT_INTERVAL          = 30  //sec
	NETWORKSCAN_INTERVAL        = 180 //sec, 3min
	MAX_HEARTBEAT_DELAY         = HEARTBEAT_INTERVAL * 2
	TM_HISTORY_CLEANUP_INTERVAL = 30 //sec

	SCAN_MEMORYSCAN      = 0 // scan RWX mem and .text of main module
	SCAN_MEMORYSCAN_EX   = 1 // scan all sections of all modules
	SCAN_MEMORY_MODULE   = 2 // fully scan specific module
	SCAN_MEMORYSCAN_FULL = 3 // scan the whole process
	SCAN_THREADSCAN      = 0x10
	SCAN_HANDLESCAN      = 0xff

	// Microsoft-Windows-Kernel-File
    EVENT_FILE_CREATE = 12 // create/open
    EVENT_FILE_DELETE = 26
    EVENT_FILE_READ = 15
    EVENT_FILE_WRITE = 16
    EVENT_FILE_RENAME = 27 // "RenamePath", rename happened

	// Microsoft-Windows-Kernel-Registry
	EVENT_REG_CREATE_KEY = 1
    EVENT_REG_OPEN_KEY = 2 // not used
    EVENT_REG_DELETE_KEY = 3
    EVENT_REG_QUERY_KEY = 4 // not used
    EVENT_REG_SET_KEY_VALUE = 5
    EVENT_REG_DELETE_KEY_VALUE = 6
    EVENT_REG_SET_INFO_KEY = 11 // change key metadata (permissions, for example)
    EVENT_REG_CLOSE_KEY = 13 // not used
    EVENT_REG_SET_SECURITY_KEY = 15

	// Microsoft-Windows-Threat-Intelligence
	ETW_TI_QUEUE_APC = 4 // there is also 24, i think its for kernel APC
	ETW_TI_SET_THREAD_CONTEXT = 5 // same thing here as above
	ETW_TI_SUSPEND_RESUME_THREAD = 15
	ETW_TI_SUSPEND_RESUME_THREAD2 = 16 // not sure why there is 2 
	ETW_TI_SUSPEND_RESUME_PROCESS = 17 // no clue why there are 4 of these...
	ETW_TI_SUSPEND_RESUME_PROCESS2 = 18
	ETW_TI_SUSPEND_RESUME_PROCESS3 = 19
	ETW_TI_SUSPEND_RESUME_PROCESS4 = 20

	TM_TYPE_EMPTY_VALUE    = 0
	TM_TYPE_API_CALL       = 1
	TM_TYPE_FILE_EVENT     = 2
	TM_TYPE_REG_EVENT      = 3
	TM_TYPE_TEXT_INTEGRITY = 4
	TM_TYPE_IAT_INTEGRITY  = 5
	TM_TYPE_GENERIC_ALERT  = 6
	EVENT_TYPE_HANDLE      = -1

	API_ARG_TYPE_EMPTY   = 0
	API_ARG_TYPE_DWORD   = 1
	API_ARG_TYPE_ASTRING = 2
	API_ARG_TYPE_WSTRING = 3
	API_ARG_TYPE_BOOL    = 4
	API_ARG_TYPE_PTR     = 5

	MAX_API_ARGS                = 10
	API_ARG_MAX_SIZE            = 520
	TM_HEADER_SIZE              = 24
	TM_MAX_DATA_SIZE            = 67624 - TM_HEADER_SIZE
	FLAG_PRINT_INFO             = 1
	FLAG_STATIC                 = 3
	FLAG_RANSOMWARE             = 4
	SCORE_STATIC                = 1
	SCORE_RANSOMWARE            = 2
	ALERT_SCORE_THRESHOLD       = 1
	THREAD_ENTRY_OUTSIDE_MODULE = 2
	THREAD_ENTRY_UNBACKED_MEM   = 3

	IS_UNSIGNED   = 0
	HAS_SIGNATURE = 1
	HASH_MISMATCH = 2

//	FILE_ACTION_DELETE = 0
//	FILE_ACTION_MODIFY = 1 << 0
//	FILE_ACTION_CREATE = 1 << 1

	OBJECT_TYPE_UNKNOWN        = 0
	OBJECT_TYPE_PROCESS        = 1
	OBJECT_TYPE_THREAD         = 2
	OBJECT_TYPE_TOKEN          = 3
	OBJECT_TYPE_DEVICE         = 4
	OBJECT_TYPE_DESKTOP        = 5
	OBJECT_TYPE_DRIVER         = 6
	OBJECT_TYPE_WORKER_FACTORY = 7
	OBJECT_TYPE_SECTION        = 8
	OBJECT_TYPE_DBGOBJECT      = 9
	OBJECT_TYPE_EVENT          = 10
	OBJECT_TYPE_DIRECTORY      = 11
	OBJECT_TYPE_FILE           = 12
	OBJECT_TYPE_SEMAPHORE      = 13
	OBJECT_TYPE_KEY            = 14
	OBJECT_TYPE_SYMLINK        = 15

	PARAMETER_ANSISTRING  = 1
	PARAMETER_POINTER     = 3
	PARAMETER_POINTER_ARR = 30
	PARAMETER_UINT32      = 4
	PARAMETER_UINT32_ARR  = 40
	PARAMETER_UINT64      = 5
	PARAMETER_UINT64_ARR  = 50
	PARAMETER_BOOLEAN     = 6
	PARAMETER_BOOLEAN_ARR = 60
	PARAMETER_BYTES       = 7

	DUCK_BANNER    = 0
	TOTORO_BANNER1 = 1
	TOTORO_BANNER2 = 2
	POLICE_BANNER  = 3
	DEFAULT_BANNER = TOTORO_BANNER1
)

// "dictionary" to allow for using string enums for bitmasks
var enums = map[string]Bitmask{
	"RWX":                    windows.PAGE_EXECUTE_READWRITE,
	"RW":                     windows.PAGE_READWRITE,
	"RX":                     windows.PAGE_EXECUTE_READ,
	"R":                      windows.PAGE_READONLY,
	"X":                      windows.PAGE_EXECUTE,
	
	"PAGE_WRITECOPY":         windows.PAGE_WRITECOPY,
	"PAGE_WRITECOMBINE":      windows.PAGE_WRITECOMBINE,
	"PAGE_EXECUTE_READWRITE": windows.PAGE_EXECUTE_READWRITE,
	"PAGE_EXECUTE":           windows.PAGE_EXECUTE,
	"PAGE_READWRITE":         windows.PAGE_READWRITE,
	"PAGE_EXECUTE_READ":      windows.PAGE_EXECUTE_READ,
	"PAGE_READONLY":          windows.PAGE_READONLY,
	"PAGE_GUARD":             windows.PAGE_GUARD,
	"PAGE_NOACCESS":          windows.PAGE_NOACCESS,
	"PAGE_TARGETS_INVALID":   windows.PAGE_TARGETS_INVALID,
	"PAGE_TARGETS_NO_UPDATE": windows.PAGE_TARGETS_NO_UPDATE,
	"PAGE_NOCACHE":           windows.PAGE_NOCACHE,

	"PROCESS_ALL_ACCESS":                windows.PROCESS_ALL_ACCESS,
	"PROCESS_CREATE_PROCESS":            windows.PROCESS_CREATE_PROCESS,
	"PROCESS_CREATE_THREAD":             windows.PROCESS_CREATE_THREAD,
	"PROCESS_DUP_HANDLE":                windows.PROCESS_DUP_HANDLE,
	"PROCESS_QUERY_INFORMATION":         windows.PROCESS_QUERY_INFORMATION,
	"PROCESS_QUERY_LIMITED_INFORMATION": windows.PROCESS_QUERY_LIMITED_INFORMATION,
	"PROCESS_SET_INFORMATION":           windows.PROCESS_SET_INFORMATION,
	"PROCESS_SET_QUOTA":                 windows.PROCESS_SET_QUOTA,
	"PROCESS_SUSPEND_RESUME":            windows.PROCESS_SUSPEND_RESUME,
	"PROCESS_TERMINATE":                 windows.PROCESS_TERMINATE,
	"PROCESS_VM_OPERATION":              windows.PROCESS_VM_OPERATION,
	"PROCESS_VM_READ":                   windows.PROCESS_VM_READ,
	"PROCESS_VM_WRITE":                  windows.PROCESS_VM_WRITE,

	"SYNCHRONIZE":  windows.SYNCHRONIZE,
	"DELETE":       windows.DELETE,
	"READ_CONTROL": windows.READ_CONTROL,
	"WRITE_DAC":    windows.WRITE_DAC,
	"WRITE_OWNER":  windows.WRITE_OWNER,

	//"THREAD_ALL_ACCESS":                windows.THREAD_ALL_ACCESS,
	"THREAD_GET_CONTEXT":               windows.THREAD_GET_CONTEXT,
	"THREAD_SET_CONTEXT":               windows.THREAD_SET_CONTEXT,
	"THREAD_DIRECT_IMPERSONATION":      windows.THREAD_DIRECT_IMPERSONATION,
	"THREAD_IMPERSONATE":               windows.THREAD_IMPERSONATE,
	"THREAD_QUERY_INFORMATION":         windows.THREAD_QUERY_INFORMATION,
	"THREAD_QUERY_LIMITED_INFORMATION": windows.THREAD_QUERY_LIMITED_INFORMATION,
	"THREAD_SET_INFORMATION":           windows.THREAD_SET_INFORMATION,
	"THREAD_SET_LIMITED_INFORMATION":   windows.THREAD_SET_LIMITED_INFORMATION,
	"THREAD_SET_THREAD_TOKEN":          windows.THREAD_SET_THREAD_TOKEN,
	"THREAD_SUSPEND_RESUME":            windows.THREAD_SUSPEND_RESUME,
	"THREAD_TERMINATE":                 windows.THREAD_TERMINATE,
	
	"FILE_ALL_ACCESS": windows.FILE_ALL_ACCESS,
	"STANDARD_RIGHTS_READ": windows.STANDARD_RIGHTS_READ,
	"STANDARD_RIGHTS_WRITE": windows.STANDARD_RIGHTS_WRITE,
	"STANDARD_RIGHTS_EXECUTE": windows.STANDARD_RIGHTS_EXECUTE,
	"FILE_GENERIC_READ": windows.FILE_GENERIC_READ,
	"FILE_GENERIC_WRITE": windows.FILE_GENERIC_WRITE,
	"FILE_GENERIC_EXECUTE": windows.FILE_GENERIC_EXECUTE,
	"FILE_EXECUTE": windows.FILE_EXECUTE,
	"FILE_READ_ATTRIBUTES": windows.FILE_READ_ATTRIBUTES,
	"FILE_WRITE_ATTRIBUTES": windows.FILE_WRITE_ATTRIBUTES,
	"FILE_READ_DATA": windows.FILE_READ_DATA,
	"FILE_WRITE_DATA": windows.FILE_WRITE_DATA,
	"FILE_READ_EA": windows.FILE_READ_EA,
	"FILE_WRITE_EA": windows.FILE_WRITE_EA,
	"FILE_ADD_FILE": windows.FILE_ADD_FILE,
	"FILE_ADD_SUBDIRECTORY": windows.FILE_ADD_SUBDIRECTORY,
	"FILE_APPEND_DATA": windows.FILE_APPEND_DATA,
	"FILE_CREATE_PIPE_INSTANCE": windows.FILE_CREATE_PIPE_INSTANCE,
	"FILE_DELETE_CHILD": windows.FILE_DELETE_CHILD,
	"FILE_LIST_DIRECTORY": windows.FILE_LIST_DIRECTORY,
	"FILE_TRAVERSE": windows.FILE_TRAVERSE,

	//TODO: other bitmask enums
	// creation flags, apc flags, etc.

	// kernel32 process creation flags
	"CREATE_BREAKAWAY_FROM_JOB": windows.CREATE_BREAKAWAY_FROM_JOB,
	"CREATE_DEFAULT_ERROR_MODE": windows.CREATE_DEFAULT_ERROR_MODE,
	"CREATE_NEW_CONSOLE": windows.CREATE_NEW_CONSOLE,
	"CREATE_NEW_PROCESS_GROUP": windows.CREATE_NEW_PROCESS_GROUP,
	"CREATE_NO_WINDOW": windows.CREATE_NO_WINDOW,
	"CREATE_PROTECTED_PROCESS": windows.CREATE_PROTECTED_PROCESS,
	"CREATE_SECURE_PROCESS": windows.CREATE_SECURE_PROCESS,
	"CREATE_PRESERVE_CODE_AUTHZ_LEVEL": windows.CREATE_PRESERVE_CODE_AUTHZ_LEVEL,
	"CREATE_SEPERATE_WOW_VDM": windows.CREATE_SEPERATE_WOW_VDM,
	"CREATE_SHARED_WOW_VDM": windows.CREATE_SHARED_WOW_VDM,
	"CREATE_SUSPENDED": windows.CREATE_SUSPENDED,
	"CREATE_UNICODE_ENVIRONMENT": windows.CREATE_UNICODE_ENVIRONMENT,
	"DEBUG_ONLY_THIS_PROCESS": windows.DEBUG_ONLY_THIS_PROCESS,
	"DEBUG_PROCESS": windows.DEBUG_PROCESS,
	"DETACHED_PROCESS": windows.DETACHED_PROCESS,
	"EXTENDED_STARTUPINFO_PRESENT": windows.EXTENDED_STARTUPINFO_PRESENT,
	"INHERIT_PARENT_AFFINITY": windows.INHERIT_PARENT_AFFINITY,
}

var magicToType = []Magic{
	{[]byte{0x4D, 0x5A}, "DOS MZ / PE File (.exe, .dll, ++)", []string{".exe, .dll, .sys, .ocx, .drv"}},
	{[]byte{0x5A, 0x4D}, "DOS ZM legacy executable (.exe)", []string{".exe"}},
	{[]byte{0x7F, 0x45, 0x4C, 0x46}, "ELF Executable", []string{".elf", ".so", ".out", ".bin"}},
	{[]byte{0x25, 0x50, 0x44, 0x46}, "Zip archive", []string{".zip"}},
	{[]byte{0x53, 0x51, 0x4C, 0x69, 0x74, 0x65, 0x20, 0x66, 0x6F, 0x72, 0x6D, 0x61, 0x74, 0x20, 0x33, 0x00}, "SQLite Database", []string{".sqlite", ".db", ".db3", ".sqlite3", "sl3"}},
	{[]byte{0x00, 0x00, 0x01, 0x00}, "Icon file", []string{".ico", ".icon", ".icns", ".cur"}},
	{[]byte{0x1F, 0x9D}, "tar archive (Lempel-Ziv-Welch algorithm)", []string{".tar.lzw", ".tar.z", ".tar"}},
	{[]byte{0x1F, 0xA0}, "tar archive (LZH algorithm)", []string{".tar.lzh", ".tar"}},
	{[]byte{0x2D, 0x6C, 0x68, 0x30, 0x2D}, "Lempel Ziv Huffman archive (method 0, no compression)", []string{".tar.lzh", ".tar.lz0", ".tar"}},
	{[]byte{0x2D, 0x6C, 0x68, 0x35, 0x2D}, "Lempel Ziv Huffman archive (method 5)", []string{".tar.lzh", ".tar"}},
	{[]byte{0x42, 0x5A, 0x68}, "Bzip2 archive", []string{".bz2", ".tbz2", ".tar.bz2"}]},
	{[]byte{0x47, 0x49, 0x46, 0x38, 0x37, 0x61}, "GIF file", []string{".gif"}},
	{[]byte{0x47, 0x49, 0x46, 0x38, 0x39, 0x61}, "GIF file", []string{".gif"}},
	{[]byte{0xFF, 0xD8, 0xFF, 0xDB}, "jpg or jpeg", []string{".jpg", ".jpeg", ".jpe"}},
	{[]byte{0xFF, 0xD8, 0xFF, 0xEE}, "jpg or jpeg", []string{".jpg", ".jpeg", ".jpe"}},
	{[]byte{0xFF, 0xD8, 0xFF, 0xE0}, "jpg or jpeg", []string{".jpg", ".jpeg", ".jpe"}]},
	{[]byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01}, "jpg or jpeg", []string{".jpg", ".jpeg", ".jpe"}},
	{[]byte{0x00, 0x00, 0x00, 0x0C, 0x6A, 0x50, 0x20, 0x20, 0x0D, 0x0A, 0x87, 0x0A}, "JPEG 2000 format", []string{".jp2", ".j2k", ".jpf", ".jpm", ".jpx"}},
	{[]byte{0xFF, 0x4F, 0xFF, 0x51}, "JPEG 2000 format", []string{".jp2", ".j2k", ".jpf", ".jpf", ".jpm", ".jpx"}},
	{[]byte{0x50, 0x4B, 0x03, 0x04}, "zip file format", []string{".zip", ".zipx"}},
	{[]byte{0x50, 0x4B, 0x05, 0x06}, "zip file format(empty archive)", []string{".zip"}},
	{[]byte{0x50, 0x4B, 0x07, 0x08}, "zip file format(spanned archive)", []string{".zip", ".z01", ".z02"}},
	{[]byte{0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00}, "Roshal ARchive (RAR), >v1.50", []string{".rar"}},
	{[]byte{0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00}, "Roshal ARchive (RAR), >v5.00", []string{".rar"}},
	{[]byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}, "Portable Network Graphics (PNG) format", []string{".png"}},
	{[]byte{0xEF, 0xBB, 0xBF}, "UTF-8 byte order mark (.txt, ++)", []string{".txt", ".html", ".css", ".json", ".xml", ".csv", ".md"}},
	{[]byte{0xFF, 0xFE}, "UTF-16LE byte order mark (.txt, ++)", []string{".txt", ".html", ".css", ".json", ".xml", ".csv", ".md"}},
	{[]byte{0xFE, 0xFF}, "UTF-16BE byte order mark (.txt, ++)",  []string{".txt", ".html", ".css", ".json", ".xml", ".csv", ".md"}},
	{[]byte{0xFF, 0xFE, 0x00, 0x00}, "UTF-32LE byte order mark (.txt, ++)", []string{".txt", ".html", ".css", ".json", ".xml", ".csv", ".md"}},
	{[]byte{0x00, 0x00, 0xFE, 0xFF}, "UTF-32BE byte order mark (.txt, ++)", []string{".txt", ".html", ".css", ".json", ".xml", ".csv", ".md"}},
	{[]byte{0xFE, 0xED, 0xFA, 0xCE}, "Mach-O executable (32-bit)", []string{".app", ".dylib", ".bundle"}},
	{[]byte{0xFE, 0xED, 0xFA, 0xCF}, "Mach-O executable (64-bit)", []string{".app", ".dylib", ".bundle"}},
	{[]byte{0xCE, 0xFA, 0xED, 0xFE}, "Mach-O executable (reverse-order, 32-bit)",[]string{".app", ".dylib", ".bundle"}},
	{[]byte{0xCF, 0xFA, 0xED, 0xFE}, "Mach-O executable (reverse-order, 64-bit)",[]string{".app", ".dylib", ".bundle"}},
	{[]byte{0x25, 0x21, 0x50, 0x53}, "PostScript Document", []string{".ps", ".eps"}},
	{[]byte{0x25, 0x21, 0x50, 0x53, 0x2D, 0x41, 0x64, 0x6F, 0x62, 0x65, 0x2D, 0x33, 0x2E, 0x30, 0x20, 0x45, 0x50, 0x53, 0x46, 0x2D, 0x33, 0x2E, 0x30}, "Encapsulated PostScript v3.0", []string{".eps"}},
	{[]byte{0x25, 0x21, 0x50, 0x53, 0x2D, 0x41, 0x64, 0x6F, 0x62, 0x65, 0x2D, 0x33, 0x2E, 0x31, 0x20, 0x45, 0x50, 0x53, 0x46, 0x2D, 0x33, 0x2E, 0x30}, "Encapsulated PostScript v3.1", []string{".eps"}},
	{[]byte{0x25, 0x50, 0x44, 0x46, 0x2D}, "PDF Document", []string{".pdf"}},
	{[]byte{0x43, 0x44, 0x30, 0x30, 0x31}, "ISO9660 CD/DVD image file", []string{".iso"}},
	{[]byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}, "Compound File Binary Format (Microsoft Office)", []string{".doc", ".xls", ".ppt", ".mdb", ".accdb"}},
	{[]byte{0x43, 0x72, 0x32, 0x34}, "Google Chrome extension or packaged app", []string{".crx", ".app"}},
	{[]byte{0x75, 0x73, 0x74, 0x61, 0x72, 0x00, 0x30, 0x30}, "tar archive", []string{".tar"}},
	{[]byte{0x75, 0x73, 0x74, 0x61, 0x72, 0x20, 0x20, 0x00}, "tar archive", []string{".tar"}},
	{[]byte{0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C}, "7-Zip archive", []string{".7z"}},
	{[]byte{0x1F, 0x8B}, "GZIP compressed file", []string{".gz", ".tgz"}},
	{[]byte{0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00}, "XZ compression utility using LZMA2 compression", []string{".xz", ".txz"}},
	{[]byte{0x00, 0x61, 0x73, 0x6D}, "WebAssembly binary format", []string{".wasm"}},
	{[]byte{0x49, 0x73, 0x5A, 0x21}, "Compressed ISO image", []string{".iso", ".cue", ".img"}},
	//TODO: add audio formats
	//TODO: add more executable types
	//TODO: lnk and other common malicious initial vector file types
}

var stars = "************************************************************************************"