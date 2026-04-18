package main

//?======================================================================+
//?   This file defines global constants and create enums for Bitmask.   |
//?======================================================================+


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

	// score response thresholds
	SCORE_STATIC_ALERT_THRESHOLD = 60
	SCORE_STATIC_FINAL_THRESHOLD = 90
	SCORE_RANSOM_ALERT_THRESHOLD = 50
	SCORE_RANSOM_FINAL_THRESHOLD = 80
	SCORE_TOTAL_ALERT_THRESHOLD  = 50
	SCORE_TOTAL_FINAL_THRESHOLD  = 80

	//
	MEMORYSCAN_INTERVAL         = 30  //sec
	THREADSCAN_INTERVAL         = 30  //sec
	HANDLESCAN_INTERVAL         = 30  // sec
	HEARTBEAT_INTERVAL          = 30  //sec
	NETWORKSCAN_INTERVAL        = 180 //sec, 3min
	MAX_HEARTBEAT_DELAY         = HEARTBEAT_INTERVAL * 2
	TM_CLEANUP_INTERVAL         = 30 //sec
	TM_CLEANUP_INTERVAL_HARD    = 30 //sec
	NUM_ENSLAVED_JANITORS 		= 50 // telemetry cleanup workers
	HANDLE_CACHE_EXPIRATION     = 3 // sec
	UNBACKED_CODE_THRESHOLD 	= 16000 // size threshold (B)
	UNBACKED_CODE_SCORE 		= 30

	//* scan types
	SCAN_MEMORYSCAN      = 0 // scan RWX mem and .text of main module
	SCAN_MEMORYSCAN_EX   = 1 // scan all sections of all modules
	SCAN_MEMORY_MODULE   = 2 // fully scan specific module
	SCAN_MEMORYSCAN_FULL = 3 // scan the whole process
	SCAN_UNBACKED_CODE   = 5 // scan for unbacked memory pages and launch additional
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

	// packet types for TelemetryHeader
	TM_TYPE_EMPTY_VALUE    = 0
	TM_TYPE_API_CALL       = 1
	TM_TYPE_TEXT_INTEGRITY = 4
	TM_TYPE_IAT_INTEGRITY  = 5
	TM_TYPE_GENERIC_ALERT  = 6
	TM_TYPE_HANDLE         = 7
	TM_TYPE_ETW_GENERIC   = 10 // Unknown ETW provider
	TM_TYPE_ETW_FILE      = 11 // Microsoft-Windows-Kernel-File
	TM_TYPE_ETW_REG       = 12 // Microsoft-Windows-Kernel-Registry
	TM_TYPE_ETW_PS        = 13 // Microsoft-Windows-Kernel-Process
	TM_TYPE_ETW_NET       = 14 // Microsoft-Windows-Kernel-Network
	TM_TYPE_ETW_TI        = 15 // Microsoft-Windows-Threat-Intelligence
	TM_TYPE_ETW_SCH       = 16 // Microsoft-Windows-TaskScheduler
	TM_TYPE_ETW_SVC       = 17 // Microsoft-Windows-Services
	TM_TYPE_ETW_SVCHOST   = 18 // Microsoft-Windows-Services-Svchost
	TM_TYPE_ETW_SCM       = 19 // Service Control Manager 

	TM_HEADER_SIZE              = 22
	TM_MAX_DATA_SIZE            = 67624 - TM_HEADER_SIZE
	FLAG_PRINT_INFO             = 1
	FLAG_STATIC                 = 3
	FLAG_RANSOMWARE             = 4
	SCORE_STATIC                = 1
	SCORE_RANSOMWARE            = 2
	THREAD_ENTRY_OUTSIDE_MODULE = 2
	THREAD_ENTRY_UNBACKED_MEM   = 3

	IS_UNSIGNED   = 0
	HAS_SIGNATURE = 1
	HASH_MISMATCH = 2

//	FILE_ACTION_DELETE = 0
//	FILE_ACTION_MODIFY = 1 << 0
//	FILE_ACTION_CREATE = 1 << 1

	//* alert types
	ALERT_SCORE_THRESHOLD       = 1
	ALERT_UNBACKED_CODE         = 2
	ALERT_DLL_INJECTION         = 3
	ALERT_PROCESS_INJECTION     = 4
	ALERT_RANSOMWARE = 9
	ALERT_PERSISTANCE = 10
	ALERT_INFOSTEALER = 11

	//* object types
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

	//* parameter types 
	PARAMETER_ANSISTRING = 1
	PARAMETER_ASTR_ARRAY = 10
	PARAMETER_UINT32 = 2
	PARAMETER_UINT32_ARRAY = 20
	PARAMETER_UINT64 = 3
	PARAMETER_UINT64_ARRAY = 30
	PARAMETER_BOOLEAN = 4
	PARAMETER_BOOLEAN_ARRAY = 40
	PARAMETER_POINTER = 5
	PARAMETER_POINTER_ARRAY =  50
	PARAMETER_BYTES = 7

	//* bitmask enum domains
	DOMAIN_GENERIC_ANY 		 = 1 
	DOMAIN_PROCESS_ACCESS 	 = 2
	DOMAIN_THREAD_ACCESS 	 = 3
	DOMAIN_FILE_ACCESS 		 = 4
	DOMAIN_MEMORY_PROTECTION = 5
	DOMAIN_ALLOCATION_TYPE   = 6
	DOMAIN_PROCESS_CREATION  = 7
	DOMAIN_THREAD_CREATION   = 8

	DUCK_BANNER    = 0
	TOTORO_BANNER1 = 1
	TOTORO_BANNER2 = 2
	POLICE_BANNER  = 3
	DEFAULT_BANNER = TOTORO_BANNER1
)

// for now 1-100 scale indicating confidence
const ( // Process Graphing interaction bitflags
	PG_DIRECT_RELATIVE Bitmask = 1 << iota 
	PG_INTERPROCESS_COMMS 
	PG_SAME_FILE_READ   
	PG_SAME_FILE_WRITE    
	PG_SAME_DIR_FS_OP     
	PG_SAME_PS_ACCESS     
	PG_SAME_MEM_ACCESS    
	PG_PROCESS_EXEC       
	PG_SHARED_SYNC        
	PG_SAME_BINARY        
)

const ( //Process Graphing interaction modifiers
	// interaction weights (how likely to directly co-operate)
	PG_DIRECT_RELATIVE_WEIGHT    = 80  // parent, child, sibling
	PG_INTERPROCESS_COMMS_WEIGHT = 70  // shared IPC channel
	PG_SAME_FILE_READ_WEIGHT     = 10  // reading same file
	PG_SAME_FILE_WRITE_WEIGHT    = 30  // writing same file
	PG_SAME_DIR_FS_OP_WEIGHT     = 10  // operating on a file in same dir
	PG_SAME_PS_ACCESS_WEIGHT     = 35  // accessing the same process (in any way)
	PG_SAME_MEM_ACCESS_WEIGHT    = 50  // accessing same memory space
	PG_PROCESS_EXEC_WEIGHT       = 80  // setting execution on process
	PG_SHARED_SYNC_WEIGHT        = 30  // sharing same sync object
	PG_SAME_BINARY_WEIGHT        = 60  // having the same exe file
)

var ( //* Handle Cache Cleanup modifiers
	HCC_MULTIPLIER_CONST = 1
	HCC_OBJECT_MULTIPLIER = 2
	HCC_TIME_MULTIPLIER = 2
	HCC_TIME_POWER = 1.5

	HCC_DEFAULT_QUOTA = 50
	HCC_TOP_PRIORITY_BONUS = 5
	HCC_OBJECT_TIER_1_SCORE = 2
	HCC_OBJECT_TIER_2_SCORE = 15
	HCC_OBJECT_TIER_3_SCORE = 40
	HCC_OBJECT_TIER_4_SCORE = 60
	HCC_OBJECT_UNKNOWN_SCORE = 70
)

// lower score indicates its more important
var ObjectTypeTier = map[uint32]int {
	OBJECT_TYPE_PROCESS: 1,
	OBJECT_TYPE_THREAD: 1,
	OBJECT_TYPE_WORKER_FACTORY: 1,
	OBJECT_TYPE_TOKEN: 1,
	OBJECT_TYPE_SECTION: 1,
	OBJECT_TYPE_ALPC_PORT: 1,
	OBJECT_TYPE_DRIVER: 1,
	OBJECT_TYPE_DESKTOP: 2,
	OBJECT_TYPE_DBGOBJECT: 2,
	OBJECT_TYPE_SESSION: 2,
	OBJECT_TYPE_JOB: 3,
	OBJECT_TYPE_ETW_REGISTRATION: 3,
	OBJECT_TYPE_ETW_CONSUMER: 3,
	OBJECT_TYPE_ETW_SDE: 3,
	OBJECT_TYPE_DIRECTORY: 3,
	OBJECT_TYPE_FILE: 3,
	OBJECT_TYPE_EVENT: 3,
	OBJECT_TYPE_SEMAPHORE: 3,
	OBJECT_TYPE_CALLBACK: 3,
	OBJECT_TYPE_WMIGUID: 3,
	OBJECT_TYPE_TIMER: 4,
	OBJECT_TYPE_IRTIMER: 4,
	OBJECT_TYPE_SYMLINK: 4,
}

type Enum struct {
	Value Bitmask
	// A domain is added for the purpose of timeline reconstruction.
	// This enables raw bitmask values to be translated into corresponding string enums.
	Domain uint8
}

// "dictionary" to allow for using string enums for bitmasks
var enums = map[string]Enum{
	/*"QUEUE_APC": ETW_TI_QUEUE_APC,
	"QUEUE APC": ETW_TI_QUEUE_APC,
	"SET_THREAD_CONTEXT": ETW_TI_SET_THREAD_CONTEXT,
	"SET THREAD CONTEXT": ETW_TI_SET_THREAD_CONTEXT,
	"SUSPEND_RESUME_THREAD": ETW_TI_SUSPEND_RESUME_THREAD,
	"SUSPEND RESUME THREAD": ETW_TI_SUSPEND_RESUME_THREAD,
	"SUSPEND_RESUME_THREAD2": ETW_TI_SUSPEND_RESUME_THREAD2,
	"SUSPEND RESUME THREAD2": ETW_TI_SUSPEND_RESUME_THREAD2,
	"SUSPEND_THREAD": ETW_TI_SUSPEND_RESUME_THREAD,
	"SUSPENDTHREAD": ETW_TI_SUSPEND_RESUME_THREAD,
	"SUSPEND_THREAD2": ETW_TI_SUSPEND_RESUME_THREAD2,
	"SUSPEND THREAD2": ETW_TI_SUSPEND_RESUME_THREAD2,
	"RESUME_THREAD": ETW_TI_SUSPEND_RESUME_THREAD,
	"RESUME THREAD": ETW_TI_SUSPEND_RESUME_THREAD,
	"RESUME_THREAD2": ETW_TI_SUSPEND_RESUME_THREAD2,
	"RESUME THREAD2": ETW_TI_SUSPEND_RESUME_THREAD2,
	"SUSPEND_RESUME_PROCESS": ETW_TI_SUSPEND_RESUME_PROCESS,
	"SUSPEND RESUME PROCESS": ETW_TI_SUSPEND_RESUME_PROCESS,*/

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