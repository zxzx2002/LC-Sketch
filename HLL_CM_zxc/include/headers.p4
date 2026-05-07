/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/
const bit<16> TYPE_MYTUNNEL = 0x1212;
const bit<16> TYPE_IPV4 = 0x800;

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;


header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header myTunnel_t {
    bit<16> proto_id;
    bit<8> load_sketch;

    bit<48> ig_tstamp;
    bit<48> eg_tstamp;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<6>    dscp;
    bit<2>    ecn;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

struct metadata {
    // HyperLogLog
    bit<32> hash_val_x;
    bit<4> register_index_j;
    bit<28> hash_val_w;
    bit<8> current_register_val_Mj; //bit 5
    bit<8> rho;         //bit 5

    // CountMin
    bit<32> index_cmsketch0;
    bit<32> index_cmsketch1;
    bit<32> index_cmsketch2;
    bit<32> index_cmsketch3;
    bit<32> index_cmsketch4;
    bit<32> index_cmsketch5;
    bit<64> value_cmsketch0;
    bit<64> value_cmsketch1;
    bit<64> value_cmsketch2;
    bit<64> value_cmsketch3;
    bit<64> value_cmsketch4;
    bit<64> value_cmsketch5;
}

struct headers {
    ethernet_t   ethernet;
    myTunnel_t   myTunnel;
    ipv4_t       ipv4;
    tcp_t        tcp;
}
