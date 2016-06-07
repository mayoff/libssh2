
find_path(LIBTOMMATH_INCLUDE_DIR tommath.h
        PATHS ${CMAKE_CURRENT_SOURCE_DIR}/../../libtommath)

find_library(LIBTOMMATH_LIBRARY tommath
        PATHS ${CMAKE_CURRENT_SOURCE_DIR}/../../libtommath)

set(LIBTOMMATH_LIBRARIES ${LIBTOMMATH_LIBRARY})
set(LIBTOMMATH_INCLUDE_DIRS ${LIBTOMMATH_INCLUDE_DIR})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(LibTomMath DEFAULT_MSG
        LIBTOMMATH_LIBRARY LIBTOMMATH_INCLUDE_DIR)

mark_as_advanced(LIBTOMMATH_INCLUDE_DIR LIBTOMMATH_LIBRARY)
