# Makefile.am
#
#       The Initial Developer of the Original Code is International
#       Business Machines Corporation. Portions created by IBM
#       Corporation are Copyright (C) 2005 International Business
#       Machines Corporation. All Rights Reserved.
#
#       This program is free software; you can redistribute it and/or modify
#       it under the terms of the Common Public License as published by
#       IBM Corporation; either version 1 of the License, or (at your option)
#       any later version.
#
#       This program is distributed in the hope that it will be useful,
#       but WITHOUT ANY WARRANTY; without even the implied warranty of
#       MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#       Common Public License for more details.
#
#       You should have received a copy of the Common Public License
#       along with this program; if not, a copy can be viewed at
#       http://www.opensource.org/licenses/cpl1.0.php.
#

noinst_LTLIBRARIES	=	libtpm_tspi.la	\
				libtpm_utils.la	

datadir = @datadir@
localedir = $(datadir)/locale
DEFS = -DLOCALEDIR=\"$(localedir)\" @DEFS@

#
# Common build flags
AM_CPPFLAGS		=	-I$(top_builddir)/include -D_LINUX

#
# Utility library
libtpm_utils_la_SOURCES	=	tpm_utils.c \
				tpm_log.c

#
# TSPI interface library
libtpm_tspi_la_SOURCES	=	tpm_tspi.c
libtpm_tspi_la_LIBADD	=	libtpm_utils.la

#
# PKCS#11 interface library
if P11_SUPPORT
noinst_LTLIBRARIES	+=	libtpm_pkcs11.la

libtpm_pkcs11_la_SOURCES=	tpm_pkcs11.c
libtpm_pkcs11_la_LIBADD	=	libtpm_utils.la
endif
