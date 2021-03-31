dnl Process this file with autoconf to create configure.

AC_INIT()
AC_CONFIG_HEADERS([config.h])

dnl search libnetfilter_queue
AC_CHECK_LIB([netfilter_queue], [nfq_nlmsg_put])

dnl functios that may not be present
AC_CHECK_FUNCS([pktb_setup] [pktb_populate] [pktb_head_size])

AC_OUTPUT
