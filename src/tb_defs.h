#ifndef _TB_DEFS_H_
#define _TB_DEFS_H_

typedef signed char tb_int8;
typedef unsigned char tb_uint8;
typedef tb_uint8 tb_byte;
typedef short tb_int16;
typedef unsigned short tb_uint16;
typedef int tb_int32;
typedef unsigned int tb_uint32;

#ifndef __cplusplus
	typedef tb_int8 tb_bool;
	#define tb_true ((tb_bool)1)
	#define tb_false ((tb_bool)0)
	#if defined(_MSC_VER) && !defined(inline)
		#define inline _inline
	#endif
#else
	typedef bool tb_bool;
	#define tb_true true
	#define tb_false false
#endif

#ifdef _WIN32
	#ifdef _MSC_VER
		#define TB_API	__stdcall
		#define TB_MEMALIGNED(n) __declspec(align(n))
		typedef __int64 tb_int64;
		typedef unsigned __int64 tb_uint64;
	#else
		#if __SIZEOF_POINTER__ == 4
			#define TB_API __attribute__((stdcall))
		#elif __SIZEOF_POINTER__ == 8
			#define TB_API
		#endif

		#define TB_MEMALIGNED(n) __attribute__((aligned(n)))
		typedef long long tb_int64;
		typedef unsigned long long tb_uint64;
	#endif

	#ifdef _WIN64
		#define TB_32BIT 0
		#define TB_64BIT 1
		typedef tb_uint64 tb_size;
		typedef tb_int64 tb_ssize;
	#else
		#define TB_32BIT 1
		#define TB_64BIT 0
		typedef tb_uint32 tb_size;
		typedef tb_int32 tb_ssize;
	#endif

	#define atoll _atoi64
	#define unlink _unlink
	#define strcasecmp stricmp
	#define strncasecmp strnicmp
	#ifndef __MINGW32__
		#define strtok_r strtok_s
	#endif

	#if defined(_MSC_VER) && _MSC_VER < 1900
		#define snprintf _snprintf
		#define vsnprintf _vsnprintf
	#endif

	#if defined(_MSC_VER) && _MSC_VER <= 1600
		typedef tb_ssize ssize_t;
	#endif

	#ifndef va_copy
		#define va_copy(dst, src) ((dst) = (src))
	#endif

	#define TB_LLFMT(t) "%I64" t
#else
	typedef long long tb_int64;
	typedef unsigned long long tb_uint64;

	#if __SIZEOF_POINTER__ == 4
		#define TB_32BIT 1
		#define TB_64BIT 0
		typedef tb_uint32 tb_size;
		typedef tb_int32 tb_ssize;
	#elif __SIZEOF_POINTER__ == 8
		#define TB_32BIT 0
		#define TB_64BIT 1
		typedef tb_uint64 tb_size;
		typedef tb_int64 tb_ssize;
	#endif

	#ifdef __i386__
		#define TB_API __attribute__((stdcall))
	#else
		#define TB_API
	#endif

	#define TB_LLFMT(t) "%ll" t
	#define TB_MEMALIGNED(n) __attribute__((aligned(n)))
#endif

#define TB_ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define TB_ALIGN(size, align) (((tb_size)(size) + ((align) - 1)) & (~((align) - 1)))
#define TB_OFFSETOF(type, member) ((tb_size)&((type *)0)->member)
#define TB_CONTAINER_OF(ptr, type, member) ((type *) ((char *) (ptr) - TB_OFFSETOF(type, member)))

// error code
#define TB_ERR_OK				0
#define TB_ERR_UNKNOWN			-1
#define TB_ERR_TIMEDOUT			-2
#define TB_ERR_PERM				-3		// Operation not permitted
#define TB_ERR_NOENT			-4		// No such file or directory
#define TB_ERR_INTR				-5		// Interrupted system call
#define TB_ERR_IO				-6		// I/O error
#define TB_ERR_2BIG				-7		// Argument list too long
#define TB_ERR_BADF				-8		// Bad file number
#define TB_ERR_AGAIN			-9		// Try again
#define TB_ERR_NOMEM			-10		// Out of memory
#define TB_ERR_ACCES			-11		// Permission denied
#define TB_ERR_FAULT			-12		// Bad address
#define TB_ERR_BUSY				-13		// Device or resource busy
#define TB_ERR_EXIST			-14		// File exists
#define TB_ERR_XDEV				-15		// Cross-device link
#define TB_ERR_NODEV			-16		// No such device
#define TB_ERR_NOTDIR			-17		// Not a directory
#define TB_ERR_ISDIR			-18		// Is a directory
#define TB_ERR_INVAL			-19		// Invalid argument
#define TB_ERR_MFILE			-20		// Too many open files
#define TB_ERR_NOSPC			-21		// No space left on device
#define TB_ERR_ROFS				-22		// Read-only file system
#define TB_ERR_PIPE				-23		// Broken pipe
#define TB_ERR_NAMETOOLONG		-24		// File name too long
#define TB_ERR_NOSYS			-25		// Invalid system call number
#define TB_ERR_NOTEMPTY			-26		// Directory not empty
#define TB_ERR_LOOP				-27		// Too many symbolic links encountered
#define TB_ERR_NOTSOCK			-28		// Socket operation on non-socket
#define TB_ERR_DESTADDRREQ		-29		// Destination address required
#define TB_ERR_MSGSIZE			-30		// Message too long
#define TB_ERR_PROTOTYPE		-31		// Protocol wrong type for socket
#define TB_ERR_NOPROTOOPT		-32		// The option is not supported by the protocol.
#define TB_ERR_PROTONOSUPPORT	-33		// Protocol not supported
#define TB_ERR_OPNOTSUPP		-34		// Operation not supported on transport endpoint
#define TB_ERR_AFNOSUPPORT		-35		// Address family not supported by protocol
#define TB_ERR_ADDRINUSE		-36		// Address already in use
#define TB_ERR_ADDRNOTAVAIL		-37		// Cannot assign requested address
#define TB_ERR_NETDOWN			-38		// Network is down
#define TB_ERR_NETUNREACH		-39		// Network is unreachable
#define TB_ERR_CONNABORTED		-40		// Software caused connection abort
#define TB_ERR_CONNRESET		-41		// Connection reset by peer
#define TB_ERR_NOBUFS			-42		// No buffer space available
#define TB_ERR_ISCONN			-43		// Transport endpoint is already connected
#define TB_ERR_NOTCONN			-44		// Transport endpoint is not connected
#define TB_ERR_SHUTDOWN			-45		// Cannot send after transport endpoint shutdown
#define TB_ERR_CONNREFUSED		-46		// Connection refused
#define TB_ERR_HOSTUNREACH		-47		// No route to host
#define TB_ERR_ALREADY			-48		// Operation already in progress
#define TB_ERR_INPROGRESS		-49		// Operation now in progress
#define TB_ERR_CANCELED			-50		// aio request was canceled before complete

#define TB_ERR_TYPE				-200	// type mismatch
#define TB_ERR_PARSE			-201	// parse error

typedef tb_uint32 tb_id_t;

typedef struct
{
	tb_int32 year;
	tb_int8  month;		//从1开始，1~12
	tb_int8  day;		//从1开始
	tb_int8  wday;		//星期日0，星期一1，星期二2，...，星期六6。其他值无效忽略。
	tb_int8  hour;		//0~23
	tb_int8  minute;	//0~59
	tb_int8  second;	//0~59
	tb_int16 msecond;	//0~999
} tb_datetime_t;

typedef struct
{
	void* buf;
	tb_int32 len;
} tb_buf_t;

#endif //_TB_DEFS_H_
