# Adds --enable-zoff to configuration options
# If no provider is loaded, there should be
# no effect.

AC_DEFUN([ZFS_AC_ZOFF], [
	AC_ARG_ENABLE([zoff],
		AS_HELP_STRING([--enable-zoff], [Enable ZFS Offloading]),
		[enable_zoff=$enableval],
		[enable_zoff="no"]
	)

	AS_IF([test "x$enable_zoff" = "xyes"],
		[ZOFF_CPPFLAGS="-DZOFF=1"
		KERNEL_ZOFF_CPPFLAGS="-DZOFF=1"])

	AC_SUBST(ZOFF_CPPFLAGS)
	AC_SUBST(KERNEL_ZOFF_CPPFLAGS)
])
