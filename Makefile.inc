OPENSOLARIS_USR_DISTDIR= ${.CURDIR}/../../cddl/contrib/opensolaris
OPENSOLARIS_SYS_DISTDIR= ${.CURDIR}/../../sys/cddl/contrib/opensolaris

IGNORE_PRAGMA=	YES

CFLAGS+=	-DNEED_SOLARIS_BOOLEAN
CFLAGS+=	-DHAVE_STRLCAT -DHAVE_STRLCPY

# Do not lint the CDDL stuff. It is all externally maintained and
# lint output is wasteful noise here.

NO_LINT=
