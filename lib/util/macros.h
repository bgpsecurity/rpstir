#ifndef _UTILS_MACROS_H
#define _UTILS_MACROS_H

/**
 * @brief
 *     number of elements in array \p x
 */
#define ELTS(x) (sizeof((x))/sizeof((x)[0]))

#define COMPILE_TIME_ASSERT(pred) \
    do {                          \
        switch (0) {              \
        case 0:                   \
        case (pred):              \
            break;                \
        }                         \
    } while (0)

/**
   @brief
       Test if the unsigned integer type @p container_type is able to
       hold any value that the unsigned integer type @p datum_type can
       hold.
*/
#define TYPE_CAN_HOLD_UINT(container_type, datum_type) \
    ((container_type)-1 >= (datum_type)-1)

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

#define NO_RETURN __attribute__((noreturn))

#else

#define WARN_PRINTF(fmtstring, vararg)
#define WARN_IF_UNUSED
#define PACKED_STRUCT NOT_IMPLEMENTED_ERROR
#define NO_RETURN

#endif

#endif
