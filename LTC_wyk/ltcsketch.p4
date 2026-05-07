#include <core.p4>
#include <t2na.p4>
#include "include/headers.p4"
#include "include/parsers.p4"

/* LTC Sketch 参数 */
#define BUCKET_COUNT 16   // w=1000个桶
#define CELLS_PER_BUCKET 4   // d=4个cell/桶
#define P_ARRAY_SIZE 5      // β=20
#define THRESHOLD_DATAPLANE 100 //数据面的阈值，相当于之前的每个检测周期的判断阈值
#define SUSPICION_INIT 100   // 初始可疑度
#define SUSPICION_THRESHOLD 120 // 报告阈值
#define CELL_BIT_WIDTH 16//每个位置8bit

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/
struct ltc_num_struct {       // LTC num Sketch 元数据结构
    bit<CELL_BIT_WIDTH>   num;              //总数
    bit<CELL_BIT_WIDTH>   frequency;        // 当前周期内出现频率
};

struct ltc_size_struct {       // LTC size Sketch 元数据结构
    bit<CELL_BIT_WIDTH>   packet_size1;  // 存储最近2个包大小(p-array)
    bit<CELL_BIT_WIDTH>   packet_size2;
};

control MyIngress(
    inout headers hdr,
    inout metadata meta,
    in ingress_intrinsic_metadata_t ig_intr_md,
    in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {

    // LTC num Sketch 数据包数量寄存器定义
    Register<ltc_num_struct, bit<32>>(64) ltc_num;//BUCKET_COUNT * CELLS_PER_BUCKET
    RegisterAction<ltc_num_struct, bit<32>, bit<CELL_BIT_WIDTH>>(ltc_num)action_ltc_num_update = {
        void apply(inout ltc_num_struct cell, out bit<CELL_BIT_WIDTH> report_result) {
            report_result = 0;
            cell.num = 1 + cell.num;
            cell.frequency = 1 + cell.frequency;
            //cell.packet_size2 = cell.packet_size1;
            //cell.packet_size1 = meta.packet_len;
            if(cell.frequency > THRESHOLD_DATAPLANE)//在控制面定期检测的时候，要frequency归零
                report_result = 1; //每个周期内，数据平面会比控制面更早检测到异常，并上传
            }};

    // LTC size Sketch 数据包大小寄存器定义
    Register<ltc_size_struct, bit<32>>(64) ltc_size;//BUCKET_COUNT * CELLS_PER_BUCKET
    RegisterAction<ltc_size_struct, bit<32>, bit<CELL_BIT_WIDTH>>(ltc_size)action_ltc_size_update = {
        void apply(inout ltc_size_struct cell, out bit<CELL_BIT_WIDTH> report_result) {
            report_result = 0;
            cell.packet_size2 = cell.packet_size1;
            cell.packet_size1 = meta.packet_len;
            }};

    /* 复现问题1：
    周期性扫描动作，由于P4寄存器只有在数据包来的时候才能访问，且不支持访问两次，
    且数据包出现是随机的，为了检查寄存器所有位置，周期性检测只能放在控制平面才能
    同时读取所有的寄存器位置。然而这会带来时延开销，是LTC的劣势
    控制平面的大致操作流程如下：
    对于bit<16>   suspicion;  // 可疑度分数(初始100)，在控制面维护一个数组，记录每个位置的可疑度
    if(time to test){           //对每个时间周期
        if (cell.frequency >= 15 )  //如果数据包出现频率超出阈值
            cell.suspicion = 1 + cell.suspicion; // 增加可疑度
        else
            cell.suspicion = cell.suspicion - 1;
        cell.frequency = 0;             //检测完毕，频率值要归零
    }

    复现问题2：
    P4中的struct能存的字段上限好像是2个，尽管目前字段数已缩短到4个
    bit<CELL_BIT_WIDTH>   num;              //总数
    bit<CELL_BIT_WIDTH>   frequency;        // 当前周期内出现频率
    //bit<CELL_BIT_WIDTH>   packet_size1;  // 存储最近2个包大小(p-array)
    //bit<CELL_BIT_WIDTH>   packet_size2;
    但仍要拆分成两组struct，放在不同的寄存器进行存储
    */

    // 哈希函数定义
    CRCPolynomial<bit<32>>(32w0x04C11DB7, true, false, true, 32w0xFFFFFFFF, 32w0xFFFFFFFF) poly0;
    CRCPolynomial<bit<32>>(32w0xEDB88320, true, false, true, 32w0xFFFFFFFF, 32w0xFFFFFFFF) poly1;
    Hash<bit<32>>(HashAlgorithm_t.CUSTOM, poly0) hash_ltc;
    Hash<bit<32>>(HashAlgorithm_t.CUSTOM, poly1) hash_flow_id;

/*************************************************************************
**************  M Y  C O N T R O L  P R O G R A M  *******************
*************************************************************************/
    // 报告可疑流动作
    action report_suspicious_flow(bit<32> flow_id) {
        //clone3(CloneType.I2E, CPU_PORT, {flow_id, meta.current_timestamp});// 克隆到控制器进行ML分析
    }

    action calculate_flow_id() {    //流ID是存在寄存器里面的，与下面的index不一样
        meta.flow_hash = hash_flow_id.get({hdr.ipv4.srcAddr, hdr.ipv4.dstAddr,
            hdr.ipv4.protocol, hdr.tcp.srcPort, hdr.tcp.dstPort});
    }

    action calculate_ltc_index() {
        meta.index_ltc = (hash_ltc.get({meta.flow_hash}))&0x003f;
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
        //meta.current_timestamp = ig_prsr_md.global_tstamp;
        hdr.myTunnel.ig_tstamp = ig_prsr_md.global_tstamp;
        meta.packet_len = hdr.ipv4.totalLen;
        calculate_flow_id();
        calculate_ltc_index();
        meta.report_flag = action_ltc_num_update.execute(meta.index_ltc);  // 更新LTC num sketch，并判断阈值
        action_ltc_size_update.execute(meta.index_ltc); //更新size寄存器
        if (meta.report_flag == 1) {
            report_suspicious_flow(meta.flow_hash);// 把流标签上传
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