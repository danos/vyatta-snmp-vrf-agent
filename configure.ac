#
AC_INIT([vyatta-snmp-vrf-agentx], [1.0], [DL-vyatta-help@att.com])
AC_PREREQ([2.63])
AC_CONFIG_SRCDIR([vyatta-snmp-vrf-agent.c])

AC_PROG_CC
AC_PROG_INSTALL

AC_MSG_CHECKING([if Routing Domain is available])
AC_RUN_IFELSE(
    [AC_LANG_PROGRAM([[
            #include <linux/rtnetlink.h>
            #include <linux/if_link.h>
            #include <sys/socket.h>
            #include <linux/rtg_domains.h>
        ]],[[
            #if !(defined(SO_RTDOMAIN) && defined(RTM_NEWRTDMN) && \
            defined(RTM_DELRTDMN) && defined(RTM_GETRTDMN) && \
            defined(VRF_NAME_SIZE) && defined(RD_DEFAULT))
            #error
            #endif
            int a = RTA_RTG_DOMAIN, b = IFLA_RTG_DOMAIN, c = RTDMN_ATTR_NAME;
        ]])
    ],
    [routing_domain_support=yes],
    [routing_domain_support=no],
    [routing_domain_support=no])
if test "x$routing_domain_support" = "xyes"; then
    AC_DEFINE(HAVE_ROUTING_DOMAIN, 1, [Have Routing Domain support])
fi
AC_MSG_RESULT([$routing_domain_support])

AC_MSG_CHECKING([for U64 typedef in net-snmp])
AC_RUN_IFELSE(
    [AC_LANG_PROGRAM([[
            #include <net-snmp/net-snmp-config.h>
            #include <net-snmp/library/int64.h>
        ]],[[
            U64 *p = 0;
        ]])
    ],
    [have_typedef_u64=yes],
    [have_typedef_u64=no],
    [have_typedef_u64=no])
if test "x$have_typedef_u64" = "xyes"; then
    AC_DEFINE([__netsnmp_u64__], [U64], [net-snmp U64 counter typedef])
else
    AC_DEFINE([__netsnmp_u64__], [struct counter64], [net-snmp U64 counter typedef])
fi
AC_MSG_RESULT([$have_typedef_u64])

AC_SUBST(CC)
AC_SUBST(DEFS)
AC_SUBST(INSTALL)
AC_CONFIG_FILES([Makefile])

AC_OUTPUT
