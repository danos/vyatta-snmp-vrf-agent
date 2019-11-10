/*
 * Note: this file originally auto-generated by mib2c using
 *       version : 1.48 $ of : mfd-top.m2c,v $
 *
 * $Id$
 */
#ifndef IPCIDRROUTETABLE_H
#define IPCIDRROUTETABLE_H

#ifdef __cplusplus
extern          "C" {
#endif


/** @addtogroup misc misc: Miscellaneous routines
 *
 * @{
 */
#include <net-snmp/library/asn1.h>
#include <net-snmp/data_access/route.h>

    /*
     * other required module components 
     */
    /* *INDENT-OFF*  */
config_require(ip-forward-mib/data_access/route)
config_require(ip-forward-mib/ipCidrRouteTable/ipCidrRouteTable_interface)
config_require(ip-forward-mib/ipCidrRouteTable/ipCidrRouteTable_data_access)
    /* *INDENT-ON*  */

    /*
     * OID, column number and enum definions for ipCidrRouteTable 
     */
#include "ipCidrRouteTable_constants.h"

    /*
     *********************************************************************
     * function declarations
     */
    void            init_ipCidrRouteTable(void);
    void            shutdown_ipCidrRouteTable(void);

    /*
     *********************************************************************
     * Table declarations
     */
/**********************************************************************
 **********************************************************************
 ***
 *** Table ipCidrRouteTable
 ***
 **********************************************************************
 **********************************************************************/
    /*
     * IP-FORWARD-MIB::ipCidrRouteTable is subid 4 of ipForward.
     * Its status is Deprecated.
     * OID: .1.3.6.1.2.1.4.24.4, length: 9
     */
    /*
     *********************************************************************
     * When you register your mib, you get to provide a generic
     * pointer that will be passed back to you for most of the
     * functions calls.
     *
     * TODO:100:r: Review all context structures
     */
    /*
     * TODO:101:o: |-> Review ipCidrRouteTable registration context.
     */
    typedef netsnmp_data_list ipCidrRouteTable_registration;

/**********************************************************************/
    /*
     * TODO:110:r: |-> Review ipCidrRouteTable data context structure.
     * This structure is used to represent the data for ipCidrRouteTable.
     */
    typedef netsnmp_route_entry ipCidrRouteTable_data;


    /*
     *********************************************************************
     * TODO:115:o: |-> Review ipCidrRouteTable undo context.
     * We're just going to use the same data structure for our
     * undo_context. If you want to do something more efficent,
     * define your typedef here.
     */
    typedef ipCidrRouteTable_data ipCidrRouteTable_undo_data;

    /*
     * TODO:120:r: |-> Review ipCidrRouteTable mib index.
     * This structure is used to represent the index for ipCidrRouteTable.
     */
    typedef struct ipCidrRouteTable_mib_index_s {

        /*
         * ipCidrRouteDest(1)/IPADDR/ASN_IPADDRESS/u_long(u_long)//l/A/w/e/r/d/h
         */
        uint32_t        ipCidrRouteDest;

        /*
         * ipCidrRouteMask(2)/IPADDR/ASN_IPADDRESS/u_long(u_long)//l/A/w/e/r/d/h
         */
        uint32_t        ipCidrRouteMask;

        /*
         * ipCidrRouteTos(3)/INTEGER32/ASN_INTEGER/long(long)//l/A/w/e/R/d/h
         */
        long            ipCidrRouteTos;

        /*
         * ipCidrRouteNextHop(4)/IPADDR/ASN_IPADDRESS/u_long(u_long)//l/A/w/e/r/d/h
         */
        uint32_t        ipCidrRouteNextHop;


    } ipCidrRouteTable_mib_index;

    /*
     * TODO:121:r: |   |-> Review ipCidrRouteTable max index length.
     * If you KNOW that your indexes will never exceed a certain
     * length, update this macro to that length.
     */
#define MAX_ipCidrRouteTable_IDX_LEN     13


    /*
     *********************************************************************
     * TODO:130:o: |-> Review ipCidrRouteTable Row request (rowreq) context.
     * When your functions are called, you will be passed a
     * ipCidrRouteTable_rowreq_ctx pointer.
     */
    typedef struct ipCidrRouteTable_rowreq_ctx_s {

    /** this must be first for container compare to work */
        netsnmp_index   oid_idx;
        oid             oid_tmp[MAX_ipCidrRouteTable_IDX_LEN];

        ipCidrRouteTable_mib_index tbl_idx;

        ipCidrRouteTable_data *data;
        ipCidrRouteTable_undo_data *undo;
        unsigned int    column_set_flags;       /* flags for set columns */


        /*
         * flags per row. Currently, the first (lower) 8 bits are reserved
         * for the user. See mfd.h for other flags.
         */
        u_int           rowreq_flags;

        /*
         * TODO:131:o: |   |-> Add useful data to ipCidrRouteTable rowreq context.
         */
        u_char          ipCidrRouteStatus;

        /*
         * storage for future expansion
         */
        netsnmp_data_list *ipCidrRouteTable_data_list;

    } ipCidrRouteTable_rowreq_ctx;

    typedef struct ipCidrRouteTable_ref_rowreq_ctx_s {
        ipCidrRouteTable_rowreq_ctx *rowreq_ctx;
    } ipCidrRouteTable_ref_rowreq_ctx;

    /*
     *********************************************************************
     * function prototypes
     */
    int
        ipCidrRouteTable_pre_request(ipCidrRouteTable_registration *
                                     user_context);
    int
        ipCidrRouteTable_post_request(ipCidrRouteTable_registration *
                                      user_context, int rc);

    int
        ipCidrRouteTable_rowreq_ctx_init(ipCidrRouteTable_rowreq_ctx *
                                         rowreq_ctx, void *user_init_ctx);
    void
        ipCidrRouteTable_rowreq_ctx_cleanup(ipCidrRouteTable_rowreq_ctx *
                                            rowreq_ctx);

    ipCidrRouteTable_data *ipCidrRouteTable_allocate_data(void);
    void            ipCidrRouteTable_release_data(ipCidrRouteTable_data *
                                                  data);

    int             ipCidrRouteTable_commit(ipCidrRouteTable_rowreq_ctx *
                                            rowreq_ctx);
    ipCidrRouteTable_rowreq_ctx
        * ipCidrRouteTable_row_find_by_mib_index(ipCidrRouteTable_mib_index
                                                 * mib_idx);

    extern const oid      ipCidrRouteTable_oid[];
    extern const int      ipCidrRouteTable_oid_size;


#include "ipCidrRouteTable_interface.h"
#include "ipCidrRouteTable_data_access.h"
    /*
     *********************************************************************
     * GET function declarations
     */

    /*
     *********************************************************************
     * GET Table declarations
     */
/**********************************************************************
 **********************************************************************
 ***
 *** Table ipCidrRouteTable
 ***
 **********************************************************************
 **********************************************************************/
    /*
     * IP-FORWARD-MIB::ipCidrRouteTable is subid 4 of ipForward.
     * Its status is Deprecated.
     * OID: .1.3.6.1.2.1.4.24.4, length: 9
     */
    /*
     * indexes
     */

    int             ipCidrRouteIfIndex_get(ipCidrRouteTable_rowreq_ctx *
                                           rowreq_ctx, long
                                           *ipCidrRouteIfIndex_val_ptr);
    int             ipCidrRouteType_get(ipCidrRouteTable_rowreq_ctx *
                                        rowreq_ctx,
                                        u_long * ipCidrRouteType_val_ptr);
    int             ipCidrRouteProto_get(ipCidrRouteTable_rowreq_ctx *
                                         rowreq_ctx,
                                         u_long *
                                         ipCidrRouteProto_val_ptr);
    int             ipCidrRouteAge_get(ipCidrRouteTable_rowreq_ctx *
                                       rowreq_ctx,
                                       long *ipCidrRouteAge_val_ptr);
    int             ipCidrRouteInfo_get(ipCidrRouteTable_rowreq_ctx *
                                        rowreq_ctx,
                                        oid ** ipCidrRouteInfo_val_ptr_ptr,
                                        size_t
                                        * ipCidrRouteInfo_val_ptr_len_ptr);
    int             ipCidrRouteNextHopAS_get(ipCidrRouteTable_rowreq_ctx *
                                             rowreq_ctx, long
                                             *ipCidrRouteNextHopAS_val_ptr);
    int             ipCidrRouteMetric1_get(ipCidrRouteTable_rowreq_ctx *
                                           rowreq_ctx, long
                                           *ipCidrRouteMetric1_val_ptr);
    int             ipCidrRouteMetric2_get(ipCidrRouteTable_rowreq_ctx *
                                           rowreq_ctx, long
                                           *ipCidrRouteMetric2_val_ptr);
    int             ipCidrRouteMetric3_get(ipCidrRouteTable_rowreq_ctx *
                                           rowreq_ctx, long
                                           *ipCidrRouteMetric3_val_ptr);
    int             ipCidrRouteMetric4_get(ipCidrRouteTable_rowreq_ctx *
                                           rowreq_ctx, long
                                           *ipCidrRouteMetric4_val_ptr);
    int             ipCidrRouteMetric5_get(ipCidrRouteTable_rowreq_ctx *
                                           rowreq_ctx, long
                                           *ipCidrRouteMetric5_val_ptr);
    int             ipCidrRouteStatus_get(ipCidrRouteTable_rowreq_ctx *
                                          rowreq_ctx,
                                          u_long *
                                          ipCidrRouteStatus_val_ptr);


    int
        ipCidrRouteTable_indexes_set_tbl_idx(ipCidrRouteTable_mib_index *
                                             tbl_idx,
                                             in_addr_t ipCidrRouteDest_val,
                                             in_addr_t ipCidrRouteMask_val,
                                             long ipCidrRouteTos_val,
                                             in_addr_t
                                             ipCidrRouteNextHop_val);
    int
        ipCidrRouteTable_indexes_set(ipCidrRouteTable_rowreq_ctx *
                                     rowreq_ctx,
                                     in_addr_t ipCidrRouteDest_val,
                                     in_addr_t ipCidrRouteMask_val,
                                     long ipCidrRouteTos_val,
                                     in_addr_t ipCidrRouteNextHop_val);



    /*
     *********************************************************************
     * SET function declarations
     */

    /*
     *********************************************************************
     * SET Table declarations
     */
/**********************************************************************
 **********************************************************************
 ***
 *** Table ipCidrRouteTable
 ***
 **********************************************************************
 **********************************************************************/
    /*
     * IP-FORWARD-MIB::ipCidrRouteTable is subid 4 of ipForward.
     * Its status is Deprecated.
     * OID: .1.3.6.1.2.1.4.24.4, length: 9
     */


    int             ipCidrRouteTable_undo_setup(ipCidrRouteTable_rowreq_ctx
                                                * rowreq_ctx);
    int
        ipCidrRouteTable_undo_cleanup(ipCidrRouteTable_rowreq_ctx *
                                      rowreq_ctx);
    int             ipCidrRouteTable_undo(ipCidrRouteTable_rowreq_ctx *
                                          rowreq_ctx);
    int             ipCidrRouteTable_commit(ipCidrRouteTable_rowreq_ctx *
                                            rowreq_ctx);
    int
        ipCidrRouteTable_undo_commit(ipCidrRouteTable_rowreq_ctx *
                                     rowreq_ctx);


    int
        ipCidrRouteIfIndex_check_value(ipCidrRouteTable_rowreq_ctx *
                                       rowreq_ctx,
                                       long ipCidrRouteIfIndex_val);
    int
        ipCidrRouteIfIndex_undo_setup(ipCidrRouteTable_rowreq_ctx *
                                      rowreq_ctx);
    int             ipCidrRouteIfIndex_set(ipCidrRouteTable_rowreq_ctx *
                                           rowreq_ctx,
                                           long ipCidrRouteIfIndex_val);
    int             ipCidrRouteIfIndex_undo(ipCidrRouteTable_rowreq_ctx *
                                            rowreq_ctx);

    int             ipCidrRouteType_check_value(ipCidrRouteTable_rowreq_ctx
                                                * rowreq_ctx,
                                                u_long
                                                ipCidrRouteType_val);
    int             ipCidrRouteType_undo_setup(ipCidrRouteTable_rowreq_ctx
                                               * rowreq_ctx);
    int             ipCidrRouteType_set(ipCidrRouteTable_rowreq_ctx *
                                        rowreq_ctx,
                                        u_long ipCidrRouteType_val);
    int             ipCidrRouteType_undo(ipCidrRouteTable_rowreq_ctx *
                                         rowreq_ctx);

    int
        ipCidrRouteProto_check_value(ipCidrRouteTable_rowreq_ctx *
                                     rowreq_ctx,
                                     u_long ipCidrRouteProto_val);
    int             ipCidrRouteProto_undo_setup(ipCidrRouteTable_rowreq_ctx
                                                * rowreq_ctx);
    int             ipCidrRouteProto_set(ipCidrRouteTable_rowreq_ctx *
                                         rowreq_ctx,
                                         u_long ipCidrRouteProto_val);
    int             ipCidrRouteProto_undo(ipCidrRouteTable_rowreq_ctx *
                                          rowreq_ctx);

    int             ipCidrRouteAge_check_value(ipCidrRouteTable_rowreq_ctx
                                               * rowreq_ctx,
                                               long ipCidrRouteAge_val);
    int             ipCidrRouteAge_undo_setup(ipCidrRouteTable_rowreq_ctx *
                                              rowreq_ctx);
    int             ipCidrRouteAge_set(ipCidrRouteTable_rowreq_ctx *
                                       rowreq_ctx,
                                       long ipCidrRouteAge_val);
    int             ipCidrRouteAge_undo(ipCidrRouteTable_rowreq_ctx *
                                        rowreq_ctx);

    int             ipCidrRouteInfo_check_value(ipCidrRouteTable_rowreq_ctx
                                                * rowreq_ctx,
                                                oid *
                                                ipCidrRouteInfo_val_ptr,
                                                size_t
                                                ipCidrRouteInfo_val_ptr_len);
    int             ipCidrRouteInfo_undo_setup(ipCidrRouteTable_rowreq_ctx
                                               * rowreq_ctx);
    int             ipCidrRouteInfo_set(ipCidrRouteTable_rowreq_ctx *
                                        rowreq_ctx,
                                        oid * ipCidrRouteInfo_val_ptr,
                                        size_t
                                        ipCidrRouteInfo_val_ptr_len);
    int             ipCidrRouteInfo_undo(ipCidrRouteTable_rowreq_ctx *
                                         rowreq_ctx);

    int
        ipCidrRouteNextHopAS_check_value(ipCidrRouteTable_rowreq_ctx *
                                         rowreq_ctx,
                                         long ipCidrRouteNextHopAS_val);
    int
        ipCidrRouteNextHopAS_undo_setup(ipCidrRouteTable_rowreq_ctx *
                                        rowreq_ctx);
    int             ipCidrRouteNextHopAS_set(ipCidrRouteTable_rowreq_ctx *
                                             rowreq_ctx, long
                                             ipCidrRouteNextHopAS_val);
    int             ipCidrRouteNextHopAS_undo(ipCidrRouteTable_rowreq_ctx *
                                              rowreq_ctx);

    int
        ipCidrRouteMetric1_check_value(ipCidrRouteTable_rowreq_ctx *
                                       rowreq_ctx,
                                       long ipCidrRouteMetric1_val);
    int
        ipCidrRouteMetric1_undo_setup(ipCidrRouteTable_rowreq_ctx *
                                      rowreq_ctx);
    int             ipCidrRouteMetric1_set(ipCidrRouteTable_rowreq_ctx *
                                           rowreq_ctx,
                                           long ipCidrRouteMetric1_val);
    int             ipCidrRouteMetric1_undo(ipCidrRouteTable_rowreq_ctx *
                                            rowreq_ctx);

    int
        ipCidrRouteMetric2_check_value(ipCidrRouteTable_rowreq_ctx *
                                       rowreq_ctx,
                                       long ipCidrRouteMetric2_val);
    int
        ipCidrRouteMetric2_undo_setup(ipCidrRouteTable_rowreq_ctx *
                                      rowreq_ctx);
    int             ipCidrRouteMetric2_set(ipCidrRouteTable_rowreq_ctx *
                                           rowreq_ctx,
                                           long ipCidrRouteMetric2_val);
    int             ipCidrRouteMetric2_undo(ipCidrRouteTable_rowreq_ctx *
                                            rowreq_ctx);

    int
        ipCidrRouteMetric3_check_value(ipCidrRouteTable_rowreq_ctx *
                                       rowreq_ctx,
                                       long ipCidrRouteMetric3_val);
    int
        ipCidrRouteMetric3_undo_setup(ipCidrRouteTable_rowreq_ctx *
                                      rowreq_ctx);
    int             ipCidrRouteMetric3_set(ipCidrRouteTable_rowreq_ctx *
                                           rowreq_ctx,
                                           long ipCidrRouteMetric3_val);
    int             ipCidrRouteMetric3_undo(ipCidrRouteTable_rowreq_ctx *
                                            rowreq_ctx);

    int
        ipCidrRouteMetric4_check_value(ipCidrRouteTable_rowreq_ctx *
                                       rowreq_ctx,
                                       long ipCidrRouteMetric4_val);
    int
        ipCidrRouteMetric4_undo_setup(ipCidrRouteTable_rowreq_ctx *
                                      rowreq_ctx);
    int             ipCidrRouteMetric4_set(ipCidrRouteTable_rowreq_ctx *
                                           rowreq_ctx,
                                           long ipCidrRouteMetric4_val);
    int             ipCidrRouteMetric4_undo(ipCidrRouteTable_rowreq_ctx *
                                            rowreq_ctx);

    int
        ipCidrRouteMetric5_check_value(ipCidrRouteTable_rowreq_ctx *
                                       rowreq_ctx,
                                       long ipCidrRouteMetric5_val);
    int
        ipCidrRouteMetric5_undo_setup(ipCidrRouteTable_rowreq_ctx *
                                      rowreq_ctx);
    int             ipCidrRouteMetric5_set(ipCidrRouteTable_rowreq_ctx *
                                           rowreq_ctx,
                                           long ipCidrRouteMetric5_val);
    int             ipCidrRouteMetric5_undo(ipCidrRouteTable_rowreq_ctx *
                                            rowreq_ctx);

    int
        ipCidrRouteStatus_check_value(ipCidrRouteTable_rowreq_ctx *
                                      rowreq_ctx,
                                      u_long ipCidrRouteStatus_val);
    int
        ipCidrRouteStatus_undo_setup(ipCidrRouteTable_rowreq_ctx *
                                     rowreq_ctx);
    int             ipCidrRouteStatus_set(ipCidrRouteTable_rowreq_ctx *
                                          rowreq_ctx,
                                          u_long ipCidrRouteStatus_val);
    int             ipCidrRouteStatus_undo(ipCidrRouteTable_rowreq_ctx *
                                           rowreq_ctx);


    int
        ipCidrRouteTable_check_dependencies(ipCidrRouteTable_rowreq_ctx *
                                            ctx);


    /*
     * DUMMY markers, ignore
     *
     * TODO:099:x: *************************************************************
     * TODO:199:x: *************************************************************
     * TODO:299:x: *************************************************************
     * TODO:399:x: *************************************************************
     * TODO:499:x: *************************************************************
     */

#ifdef __cplusplus
}
#endif
#endif                          /* IPCIDRROUTETABLE_H */
/**  @} */

