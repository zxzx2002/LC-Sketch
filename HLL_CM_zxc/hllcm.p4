/* -*- P4_16 -*- */
#include <core.p4>
#include <t2na.p4>

#include "include/headers.p4"
#include "include/parsers.p4"

#define HLL_NUM_REGISTERS_EXPONENT 4
#define HLL_NUM_REGISTERS (1 << HLL_NUM_REGISTERS_EXPONENT)
#define HLL_REGISTER_INDEX_BIT_WIDTH   HLL_NUM_REGISTERS_EXPONENT
#define HLL_CELL_BIT_WIDTH 8 //bit 5
#define HLL_HASH_BIT_WIDTH 32
#define HLL_HASH_VAL_BIT_WIDTH (HLL_HASH_BIT_WIDTH - HLL_REGISTER_INDEX_BIT_WIDTH)
#define ZX 28//(HLL_HASH_BIT_WIDTH - HLL_REGISTER_INDEX_BIT_WIDTH)

#define COUNTMIN_NUM_REGISTERS 64//32个位置
#define COUNTMIN_CELL_BIT_WIDTH 64//每个位置64bit大小

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/
control MyIngress(
        inout headers hdr,
        inout metadata meta,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {

    /*************************************************************************
    *******************Define HyperLogLog and cm-sketch******************
    *************************************************************************/
    #define HLL_REGISTER(num) Register<bit<HLL_CELL_BIT_WIDTH>, bit<32>>(HLL_NUM_REGISTERS) hllsketch##num;\
    RegisterAction<bit<HLL_CELL_BIT_WIDTH>, bit<32>, bit<HLL_CELL_BIT_WIDTH>>(hllsketch##num) \
        action_hllsketch##num = {\
            void apply(inout bit<HLL_CELL_BIT_WIDTH> value_hllsketch##num, out bit<HLL_CELL_BIT_WIDTH> read_value_hllsketch##num) {\
                read_value_hllsketch##num = value_hllsketch##num;\
                if(read_value_hllsketch##num < meta.rho){value_hllsketch##num = meta.rho;}\
            }};

    #define COUNTMIN_REGISTER(num) Register<bit<COUNTMIN_CELL_BIT_WIDTH>, bit<32>>(COUNTMIN_NUM_REGISTERS) cmsketch##num; \
    RegisterAction<bit<64>, bit<32>, bit<64>>(cmsketch##num) \
        action_cmsketch##num = {\
            void apply(inout bit<64> value_cmsketch##num, out bit<64> read_value_cmsketch##num) {\
                read_value_cmsketch##num = value_cmsketch##num;\
                value_cmsketch##num = read_value_cmsketch##num + 1;\
            }};\

    HLL_REGISTER(0)
    HLL_REGISTER(1)
    COUNTMIN_REGISTER(0)
    COUNTMIN_REGISTER(1)
    COUNTMIN_REGISTER(2)
    COUNTMIN_REGISTER(3)
    COUNTMIN_REGISTER(4)
    COUNTMIN_REGISTER(5)

    CRCPolynomial<bit<32>>(32w0x04C11DB8, // polynomial
                           true, false, false, 32w0xFFFFFFFF, 32w0xFFFFFFFF) poly_hll;
    CRCPolynomial<bit<32>>(32w0x04C11DB7, // polynomial
                           true, false, false, 32w0xFFFFFFFF, 32w0xFFFFFFFF) poly0;
    CRCPolynomial<bit<32>>(32w0xEDB88320, // polynomial
                           true, false, false, 32w0xFFFFFFFF, 32w0xFFFFFFFF) poly1;
    CRCPolynomial<bit<32>>(32w0xDB710641, // polynomial
                           true, false, false, 32w0xFFFFFFFF, 32w0xFFFFFFFF) poly2;
    CRCPolynomial<bit<32>>(32w0x2D0F2373, // polynomial
                           true, false, false, 32w0xFFFFFFFF, 32w0xFFFFFFFF) poly3;
    CRCPolynomial<bit<32>>(32w0x67992C8E, // polynomial
                           true, false, false, 32w0xFFFFFFFF, 32w0xFFFFFFFF) poly4;
    CRCPolynomial<bit<32>>(32w0x55D5AA8C, // polynomial
                           true, false, false, 32w0xFFFFFFFF, 32w0xFFFFFFFF) poly5;

   Hash<bit<32>>(HashAlgorithm_t.CUSTOM, poly_hll) hll_hash;
   Hash<bit<32>>(HashAlgorithm_t.CUSTOM, poly0) myhash0;
   Hash<bit<32>>(HashAlgorithm_t.CUSTOM, poly1) myhash1;
   Hash<bit<32>>(HashAlgorithm_t.CUSTOM, poly2) myhash2;
   Hash<bit<32>>(HashAlgorithm_t.CUSTOM, poly3) myhash3;
   Hash<bit<32>>(HashAlgorithm_t.CUSTOM, poly4) myhash4;
   Hash<bit<32>>(HashAlgorithm_t.CUSTOM, poly5) myhash5;

/*************************************************************************
****************************CM-Sketch Program*********************************
*************************************************************************/
    action hash_hllsketch(){
        meta.hash_val_x = (hll_hash.get({ hdr.ipv4.srcAddr }))&0x003f;
        meta.register_index_j = meta.hash_val_x[3:0]; //[(HLL_REGISTER_INDEX_BIT_WIDTH-1):0]
        meta.hash_val_w = meta.hash_val_x[31:HLL_REGISTER_INDEX_BIT_WIDTH];
    }
    action count_hllsketch0() {action_hllsketch0.execute((bit<32>)meta.register_index_j);}
    action count_hllsketch1() {action_hllsketch1.execute((bit<32>)meta.register_index_j);}

    action hash_cmsketch0() {meta.index_cmsketch0 = (myhash0.get({ hdr.ipv4.srcAddr }))&0x003f; }
    action hash_cmsketch1() {meta.index_cmsketch1 = (myhash1.get({ hdr.ipv4.srcAddr }))&0x003f; }
    action hash_cmsketch2() {meta.index_cmsketch2 = (myhash2.get({ hdr.ipv4.srcAddr }))&0x003f; }
    action hash_cmsketch3() {meta.index_cmsketch3 = (myhash3.get({ hdr.ipv4.srcAddr }))&0x003f; }
    action hash_cmsketch4() {meta.index_cmsketch4 = (myhash4.get({ hdr.ipv4.srcAddr }))&0x003f; }
    action hash_cmsketch5() {meta.index_cmsketch5 = (myhash5.get({ hdr.ipv4.srcAddr }))&0x003f; }
    action count_cmsketch0() {meta.value_cmsketch0 = action_cmsketch0.execute(meta.index_cmsketch0);}
    action count_cmsketch1() {meta.value_cmsketch1 = action_cmsketch1.execute(meta.index_cmsketch1);}
    action count_cmsketch2() {meta.value_cmsketch2 = action_cmsketch2.execute(meta.index_cmsketch2);}
    action count_cmsketch3() {meta.value_cmsketch3 = action_cmsketch3.execute(meta.index_cmsketch3);}
    action count_cmsketch4() {meta.value_cmsketch4 = action_cmsketch4.execute(meta.index_cmsketch4);}
    action count_cmsketch5() {meta.value_cmsketch5 = action_cmsketch5.execute(meta.index_cmsketch5);}

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
        if (hdr.ipv4.isValid()) { // 10.0.1.2
            hash_hllsketch();
            //count meta.rho
            if (meta.hash_val_x == 0) {meta.rho = ZX + 1; }
            else if ((bit<28>)meta.hash_val_w[1:0] == meta.hash_val_w){meta.rho = ZX - 1;}//28 = HLL_HASH_VAL_BIT_WIDTH
            else if ((bit<28>)meta.hash_val_w[2:0] == meta.hash_val_w){meta.rho = ZX - 2;}
            else if ((bit<28>)meta.hash_val_w[3:0] == meta.hash_val_w){meta.rho = ZX - 3;}
            else if ((bit<28>)meta.hash_val_w[4:0] == meta.hash_val_w){meta.rho = ZX - 4;}
            else if ((bit<28>)meta.hash_val_w[5:0] == meta.hash_val_w){meta.rho = ZX - 5;}
            else if ((bit<28>)meta.hash_val_w[6:0] == meta.hash_val_w){meta.rho = ZX - 6;}
            else if ((bit<28>)meta.hash_val_w[7:0] == meta.hash_val_w){meta.rho = ZX - 7;}
            else if ((bit<28>)meta.hash_val_w[8:0] == meta.hash_val_w){meta.rho = ZX - 8;}
            else if ((bit<28>)meta.hash_val_w[9:0] == meta.hash_val_w){meta.rho = ZX - 9;}
            else if ((bit<28>)meta.hash_val_w[10:0] == meta.hash_val_w){meta.rho = ZX - 10;}
            else if ((bit<28>)meta.hash_val_w[11:0] == meta.hash_val_w){meta.rho = ZX - 11;}
            else if ((bit<28>)meta.hash_val_w[12:0] == meta.hash_val_w){meta.rho = ZX - 12;}
            else if ((bit<28>)meta.hash_val_w[13:0] == meta.hash_val_w){meta.rho = ZX - 13;}
            else if ((bit<28>)meta.hash_val_w[14:0] == meta.hash_val_w){meta.rho = ZX - 14;}
            else if ((bit<28>)meta.hash_val_w[15:0] == meta.hash_val_w){meta.rho = ZX - 15;}
            else if ((bit<28>)meta.hash_val_w[16:0] == meta.hash_val_w){meta.rho = ZX - 16;}
            else if ((bit<28>)meta.hash_val_w[17:0] == meta.hash_val_w){meta.rho = ZX - 17;}
            else if ((bit<28>)meta.hash_val_w[18:0] == meta.hash_val_w){meta.rho = ZX - 18;}
            else if ((bit<28>)meta.hash_val_w[19:0] == meta.hash_val_w){meta.rho = ZX - 19;}
            else if ((bit<28>)meta.hash_val_w[20:0] == meta.hash_val_w){meta.rho = ZX - 20;}
            else if ((bit<28>)meta.hash_val_w[21:0] == meta.hash_val_w){meta.rho = ZX - 21;}
            else if ((bit<28>)meta.hash_val_w[22:0] == meta.hash_val_w){meta.rho = ZX - 22;}
            else if ((bit<28>)meta.hash_val_w[23:0] == meta.hash_val_w){meta.rho = ZX - 23;}
            else if ((bit<28>)meta.hash_val_w[24:0] == meta.hash_val_w){meta.rho = ZX - 24;}
            else if ((bit<28>)meta.hash_val_w[25:0] == meta.hash_val_w){meta.rho = ZX - 25;}
            else if ((bit<28>)meta.hash_val_w[26:0] == meta.hash_val_w){meta.rho = ZX - 26;}
            else { meta.rho = 1; }

            //renew hllsketch
            count_hllsketch0();
            count_hllsketch1();

            //cmsketch
            hash_cmsketch0();
            hash_cmsketch1();
            hash_cmsketch2();
            hash_cmsketch3();
            hash_cmsketch4();
            hash_cmsketch5();

            count_cmsketch0();
            count_cmsketch1();
            count_cmsketch2();
            count_cmsketch3();
            count_cmsketch4();
            count_cmsketch5();
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
    apply {
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