#ifndef _UTILS_MACROS_H
#define _UTILS_MACROS_H

#define COMPILE_TIME_ASSERT(pred) \
	do { \
		switch(0) { \
			case 0: \
			case (pred): \
				break; \
		} \
	} while (false)

#ifdef __GNUC__

  // check printfs
#ifndef __APPLE__
#define WARN_PRINTF(fmtstring, vararg) \
      __attribute__ ((format (printf, fmtstring, vararg)))
#else
#define WARN_PRINTF(fmtstring, vararg)
#endif

  // warn if the return value isn't used..
#define WARN_IF_UNUSED __attribute__ ((warn_unused_result))

#define PACKED_STRUCT __attribute__((__packed__))

#else

#define WARN_PRINTF(fmtstring, vararg)
#define WARN_IF_UNUSED
#define PACKED_STRUCT NOT_IMPLEMENTED_ERROR

#endif

#endif
