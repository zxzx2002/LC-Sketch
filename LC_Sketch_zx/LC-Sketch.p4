//108 server + 33 switch
#include <core.p4>
#include <tna.p4>

#include "include/headers.p4"
#include "include/parsers.p4"

/* CONSTANTS */
#define BUCKET_LENGTH1 16//第一层有16位置
#define BUCKET_LENGTH2 8//第二层有8位置
#define BUCKET_LENGTH3 4//第三层有4位置
#define CELL_BIT_WIDTH 8//每个位置8bit
#define THRE 256 //进位的阈值

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/
struct mv_struct{
    bit<CELL_BIT_WIDTH> hi;  //计数
    bit<CELL_BIT_WIDTH> lo; //存流标签(完整哈希结果）
    //bit<CELL_BIT_WIDTH> num;
};

control MyIngress(
        inout headers hdr,
        inout metadata meta,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {

    Register<mv_struct, bit<32>>(BUCKET_LENGTH1) sketch1;
    RegisterAction<mv_struct, bit<32>, bit<CELL_BIT_WIDTH>>(sketch1) action_sketch1 = {
        void apply(inout mv_struct value_sketch1, out bit<CELL_BIT_WIDTH> read_value_sketch1) {
            mv_struct value = value_sketch1;
            if(value_sketch1.hi > THRE){value_sketch1.hi = 0; }
            else if(value_sketch1.hi == 0){value_sketch1.lo = (bit<CELL_BIT_WIDTH>)hdr.ipv4.srcAddr;}
            else{
                if((bit<CELL_BIT_WIDTH>)hdr.ipv4.srcAddr == value_sketch1.lo){
                    value_sketch1.hi = value.hi + 1;
                    meta.HCB = 1;
                }
            }
            read_value_sketch1 = value_sketch1.hi;
            }};

    Register<mv_struct, bit<32>>(BUCKET_LENGTH2) sketch2;
    RegisterAction<mv_struct, bit<32>, bit<CELL_BIT_WIDTH>>(sketch2) action_sketch2 = {
        void apply(inout mv_struct value_sketch2, out bit<CELL_BIT_WIDTH> read_value_sketch2) {
            mv_struct value = value_sketch2;
            if(value_sketch2.hi > THRE){value_sketch2.hi = 0; }
            else if(value_sketch2.hi == 0){value_sketch2.lo = (bit<CELL_BIT_WIDTH>)hdr.ipv4.srcAddr;}
            else{
                if((bit<CELL_BIT_WIDTH>)hdr.ipv4.srcAddr == value_sketch2.lo){
                    value_sketch2.hi = value.hi + 1;
                    meta.HCB = 1;
                }
            }
            read_value_sketch2 = value_sketch2.hi;
            }};

    Register<mv_struct, bit<32>>(BUCKET_LENGTH3) sketch3;
    RegisterAction<mv_struct, bit<32>, bit<CELL_BIT_WIDTH>>(sketch3) action_sketch3 = {
        void apply(inout mv_struct value_sketch3, out bit<CELL_BIT_WIDTH> read_value_sketch3) {
            mv_struct value = value_sketch3;
            if(value_sketch3.hi > THRE){value_sketch3.hi = 0; }
            else if(value_sketch3.hi == 0){value_sketch3.lo = (bit<CELL_BIT_WIDTH>)hdr.ipv4.srcAddr;}
            else{
                if((bit<CELL_BIT_WIDTH>)hdr.ipv4.srcAddr == value_sketch3.lo){
                    value_sketch3.hi = value.hi + 1;
                    meta.HCB = 1;
                }
            }
            read_value_sketch3 = value_sketch3.hi;
            }};

    Register<mv_struct, bit<32>>(BUCKET_LENGTH1) HCB;
    RegisterAction<mv_struct, bit<32>, bit<CELL_BIT_WIDTH>>(HCB) action_HCB = {
        void apply(inout mv_struct value_HCB, out bit<CELL_BIT_WIDTH> read_value_HCB) {
            mv_struct value = value_HCB;
            value_HCB.hi = value.hi + 1;
            value_HCB.lo = (bit<CELL_BIT_WIDTH>)hdr.ipv4.srcAddr;
            }};

    CRCPolynomial<bit<32>>(32w0x04C11DB7, 
                            true,  false,  true,  32w0xFFFFFFFF, 32w0xFFFFFFFF) poly0;
    CRCPolynomial<bit<32>>(32w0xEDB88320, // polynomial
                           true, false, true, 32w0xFFFFFFFF, 32w0xFFFFFFFF) poly1;
    CRCPolynomial<bit<32>>(32w0xDB710641, // polynomial
                           true, false, true, 32w0xFFFFFFFF, 32w0xFFFFFFFF) poly2;

    Hash<bit<32>>(HashAlgorithm_t.CUSTOM, poly0) myhash1;
    Hash<bit<32>>(HashAlgorithm_t.CUSTOM, poly1) myhash2;
    Hash<bit<32>>(HashAlgorithm_t.CUSTOM, poly2) myhash3;

    action get_index1() {meta.index = (myhash1.get({ hdr.ipv4.srcAddr, hdr.ipv4.dstAddr }))&0x000f; }
    action get_index2() {meta.index = (myhash2.get({ hdr.ipv4.srcAddr, hdr.ipv4.dstAddr }))&0x0007; }
    action get_index3() {meta.index = (myhash3.get({ hdr.ipv4.srcAddr, hdr.ipv4.dstAddr }))&0x0003; }
    
    table tbl_get_index1 {actions = {get_index1;} size = 64; const default_action = get_index1();}
    table tbl_get_index2 {actions = {get_index2;} size = 64; const default_action = get_index2();}
    table tbl_get_index3 {actions = {get_index3;} size = 64; const default_action = get_index3();}

/*************************************************************************
**************  M Y  C O N T R O L  P R O G R A M  *******************
*************************************************************************/
    action add_header(){
        hdr.myTunnel.setValid();
        hdr.myTunnel.proto_id = TYPE_IPV4;
	    hdr.ethernet.etherType = TYPE_MYTUNNEL;
        //注意添加包头之后，解析顺序要与parser.p4一致
    }

    action drop(){
		ig_dprsr_md.drop_ctl = 0x1;
	}

    action set_egress_port(bit<9> egress_port){
        ig_tm_md.ucast_egress_port = egress_port;
    }

    table forwarding {
        key = {ig_intr_md.ingress_port: exact;}
        actions = {set_egress_port; drop; NoAction;}
        size = 64;
        default_action = drop;
    }

    apply {
        hdr.myTunnel.ig_tstamp = ig_prsr_md.global_tstamp;
        add_header();
        
        tbl_get_index1.apply();// hash to get index
        meta.value1 = action_sketch1.execute(meta.index); //先更新第一层
        if(meta.HCB == 1) action_HCB.execute(meta.index); //判断冷热桶
        if(meta.value1 == THRE){ //第一层满了，更新第二层
            meta.value2 = action_sketch2.execute(meta.index);
            if(meta.value2 == THRE){ //第二层满了，更新第三层  如果设置为2层，这里就可以注释掉
                tbl_get_index3.apply();
                meta.value3 = action_sketch3.execute(meta.index);
            }
        }
        forwarding.apply();
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/
control MyEgress(inout headers hdr,
	inout metadata meta,
	in egress_intrinsic_metadata_t eg_intr_md,
	in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
	inout egress_intrinsic_metadata_for_deparser_t eg_intr_dprs_md,
	inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md){
	apply{
	    hdr.myTunnel.eg_tstamp = eg_intr_md_from_prsr.global_tstamp;
	}
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/
Pipeline(MyIngressParser(),
         MyIngress(),
         MyIngressDeparser(),
         MyEgressParser(),
         MyEgress(),
         MyEgressDeparser()) pipe;
Switch(pipe) main;