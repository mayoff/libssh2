
find_path(LIBTOMCRYPT_INCLUDE_DIR tomcrypt.h
            PATHS ${CMAKE_CURRENT_SOURCE_DIR}/../../libtomcrypt/src/headers)

find_library(LIBTOMCRYPT_LIBRARY tomcrypt
            PATHS ${CMAKE_CURRENT_SOURCE_DIR}}/../../libtomcrypt)

set(LIBTOMCRYPT_LIBRARIES ${LIBTOMCRYPT_LIBRARY})
set(LIBTOMCRYPT_INCLUDE_DIRS ${LIBTOMCRYPT_INCLUDE_DIR})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(LibTomCrypt DEFAULT_MSG
            LIBTOMCRYPT_LIBRARY LIBTOMCRYPT_INCLUDE_DIR)

mark_as_advanced(LIBTOMCRYPT_INCLUDE_DIR LIBTOMCRYPT_LIBRARY)
