#ifndef SEC_H
#define SEC_H

#include <wincrypt.h>
#include <wintrust.h>

#define SECURITY_WIN32
#include <security.h>
#include <sspi.h>

#define SCHANNEL_USE_BLACKLISTS
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
#ifdef MIDL_PASS
    [size_is(MaximumLength / 2), length_is((Length) / 2) ] USHORT * Buffer;
#else // MIDL_PASS
    _Field_size_bytes_part_opt_(MaximumLength, Length) PWCH   Buffer;
#endif // MIDL_PASS
} UNICODE_STRING;
typedef UNICODE_STRING *PUNICODE_STRING;
typedef const UNICODE_STRING *PCUNICODE_STRING;
    // then you must define UNICODE_STRING and PUNICODE_STRING
    // or include Ntdef.h, SubAuth.h or Winternl.h.
#include <schannel.h>

#endif
