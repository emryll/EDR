package main

const (
	//TODO: creation flags
	//TODO: memory protection constants
	//TODO: thread/process access constants
	//TODO: integrity level enums
	MAX_PATH                  = 260 // MAX_PATH from windows.h
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

	MEMORYSCAN_INTERVAL         = 45  //sec
	THREADSCAN_INTERVAL         = 45  //sec
	HEARTBEAT_INTERVAL          = 30  //sec
	NETWORKSCAN_INTERVAL        = 180 //sec, 3min
	MAX_HEARTBEAT_DELAY         = HEARTBEAT_INTERVAL * 2
	TM_HISTORY_CLEANUP_INTERVAL = 30 //sec

	SCAN_MEMORYSCAN      = 0 // scan RWX mem and .text of main module
	SCAN_MEMORYSCAN_EX   = 1 // scan all sections of all modules
	SCAN_MEMORY_MODULE   = 2 // fully scan specific module
	SCAN_MEMORYSCAN_FULL = 3 // scan the whole process

	TM_TYPE_EMPTY_VALUE    = 0
	TM_TYPE_API_CALL       = 1
	TM_TYPE_FILE_EVENT     = 2
	TM_TYPE_REG_EVENT      = 3
	TM_TYPE_TEXT_INTEGRITY = 4
	TM_TYPE_IAT_INTEGRITY  = 5
	TM_TYPE_GENERIC_ALERT  = 6

	API_ARG_TYPE_EMPTY   = 0
	API_ARG_TYPE_DWORD   = 1
	API_ARG_TYPE_ASTRING = 2
	API_ARG_TYPE_WSTRING = 3
	API_ARG_TYPE_BOOL    = 4
	API_ARG_TYPE_PTR     = 5

	MAX_API_ARGS     = 10
	API_ARG_MAX_SIZE = 520
	TM_HEADER_SIZE   = 24
	TM_MAX_DATA_SIZE = 67624 - TM_HEADER_SIZE

	IS_UNSIGNED   = 0
	HAS_SIGNATURE = 1
	HASH_MISMATCH = 2

	FILE_ACTION_DELETE = 0
	FILE_ACTION_MODIFY = 1 << 0
	FILE_ACTION_CREATE = 1 << 1

	GROUP_LOCAL_MEM_ALLOC     = "mem_alloc"
	GROUP_REMOTE_MEM_ALLOC    = "remote_mem_alloc"
	GROUP_LOCAL_MEM_PROTECT   = "mem_protect"
	GROUP_REMOTE_MEM_PROTECT  = "remote_mem_protect"
	GROUP_FILE_EVENT          = "file_event"
	GROUP_REG_EVENT           = "reg_event"
	GROUP_INVALID_API_OPTIONS = "invalid_api"
	GROUP_UNKNOWN_API         = "unknown_api"

	DUCK_BANNER    = 0
	TOTORO_BANNER1 = 1
	TOTORO_BANNER2 = 2
	POLICE_BANNER  = 3
	DEFAULT_BANNER = TOTORO_BANNER1
)

var magicToType = []Magic{
	{[]byte{0x4D, 0x5A}, "DOS MZ / PE File (.exe, .dll, ++)"},
	{[]byte{0x5A, 0x4D}, "DOS ZM legacy executable (.exe)"},
	{[]byte{0x7F, 0x45, 0x4C, 0x46}, "ELF Executable"},
	{[]byte{0x25, 0x50, 0x44, 0x46}, "Zip archive"},
	{[]byte{0x53, 0x51, 0x4C, 0x69, 0x74, 0x65, 0x20, 0x66, 0x6F, 0x72, 0x6D, 0x61, 0x74, 0x20, 0x33, 0x00}, "SQLite Database"},
	{[]byte{0x00, 0x00, 0x01, 0x00}, "Icon file"},
	{[]byte{0x1F, 0x9D}, "tar archive (Lempel-Ziv-Welch algorithm)"},
	{[]byte{0x1F, 0xA0}, "tar archive (LZH algorithm)"},
	{[]byte{0x2D, 0x6C, 0x68, 0x30, 0x2D}, "Lempel Ziv Huffman archive (method 0, no compression)"},
	{[]byte{0x2D, 0x6C, 0x68, 0x35, 0x2D}, "Lempel Ziv Huffman archive (method 5)"},
	{[]byte{0x42, 0x5A, 0x68}, "Bzip2 archive"},
	{[]byte{0x47, 0x49, 0x46, 0x38, 0x37, 0x61}, "GIF file"},
	{[]byte{0x47, 0x49, 0x46, 0x38, 0x39, 0x61}, "GIF file"},
	{[]byte{0xFF, 0xD8, 0xFF, 0xDB}, "jpg or jpeg"},
	{[]byte{0xFF, 0xD8, 0xFF, 0xEE}, "jpg or jpeg"},
	{[]byte{0xFF, 0xD8, 0xFF, 0xE0}, "jpg or jpeg"},
	{[]byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01}, "jpg or jpeg"},
	{[]byte{0x00, 0x00, 0x00, 0x0C, 0x6A, 0x50, 0x20, 0x20, 0x0D, 0x0A, 0x87, 0x0A}, "JPEG 2000 format"},
	{[]byte{0xFF, 0x4F, 0xFF, 0x51}, "JPEG 2000 format"},
	{[]byte{0x50, 0x4B, 0x03, 0x04}, "zip file format"},
	{[]byte{0x50, 0x4B, 0x05, 0x06}, "zip file format(empty archive)"},
	{[]byte{0x50, 0x4B, 0x07, 0x08}, "zip file format(spanned archive)"},
	{[]byte{0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00}, "Roshal ARchive (RAR), >v1.50"},
	{[]byte{0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00}, "Roshal ARchive (RAR), >v5.00"},
	{[]byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}, "Portable Network Graphics (PNG) format"},
	{[]byte{0xEF, 0xBB, 0xBF}, "UTF-8 byte order mark (.txt, ++)"},
	{[]byte{0xFF, 0xFE}, "UTF-16LE byte order mark (.txt, ++)"},
	{[]byte{0xFE, 0xFF}, "UTF-16BE byte order mark (.txt, ++)"},
	{[]byte{0xFF, 0xFE, 0x00, 0x00}, "UTF-32LE byte order mark (.txt, ++)"},
	{[]byte{0x00, 0x00, 0xFE, 0xFF}, "UTF-32BE byte order mark (.txt, ++)"},
	{[]byte{0xFE, 0xED, 0xFA, 0xCE}, "Mach-O executable (32-bit)"},
	{[]byte{0xFE, 0xED, 0xFA, 0xCF}, "Mach-O executable (64-bit)"},
	{[]byte{0xCE, 0xFA, 0xED, 0xFE}, "Mach-O executable (reverse-order, 32-bit)"},
	{[]byte{0xCF, 0xFA, 0xED, 0xFE}, "Mach-O executable (reverse-order, 64-bit)"},
	{[]byte{0x25, 0x21, 0x50, 0x53}, "PostScript Document"},
	{[]byte{0x25, 0x21, 0x50, 0x53, 0x2D, 0x41, 0x64, 0x6F, 0x62, 0x65, 0x2D, 0x33, 0x2E, 0x30, 0x20, 0x45, 0x50, 0x53, 0x46, 0x2D, 0x33, 0x2E, 0x30}, "Encapsulated PostScript v3.0"},
	{[]byte{0x25, 0x21, 0x50, 0x53, 0x2D, 0x41, 0x64, 0x6F, 0x62, 0x65, 0x2D, 0x33, 0x2E, 0x31, 0x20, 0x45, 0x50, 0x53, 0x46, 0x2D, 0x33, 0x2E, 0x30}, "Encapsulated PostScript v3.1"},
	{[]byte{0x25, 0x50, 0x44, 0x46, 0x2D}, "PDF Document"},
	{[]byte{0x43, 0x44, 0x30, 0x30, 0x31}, "ISO9660 CD/DVD image file"},
	{[]byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}, "Compound File Binary Format (Microsoft Office)"},
	{[]byte{0x43, 0x72, 0x32, 0x34}, "Google Chrome extension or packaged app"},
	{[]byte{0x75, 0x73, 0x74, 0x61, 0x72, 0x00, 0x30, 0x30}, "tar archive"},
	{[]byte{0x75, 0x73, 0x74, 0x61, 0x72, 0x20, 0x20, 0x00}, "tar archive"},
	{[]byte{0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C}, "7-Zip archive"},
	{[]byte{0x1F, 0x8B}, "GZIP compressed file"},
	{[]byte{0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00}, "XZ compression utility using LZMA2 compression"},
	{[]byte{0x00, 0x61, 0x73, 0x6D}, "WebAssembly binary format"},
	{[]byte{0x49, 0x73, 0x5A, 0x21}, "Compressed ISO image"},
	//TODO: add audio formats
	//TODO: add more executable types
	//TODO: lnk and other common malicious initial vector file types
}
