#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<8>  TYPE_TCP  = 6;

#define BLOOM_FILTER_ENTRIES 4096
#define BLOOM_FILTER_BIT_WIDTH 1

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
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
    /* empty */
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t        tcp;
}

/****************************************************************
parser是一个有限状态机。从 start 状态开始，每一个状态便解析一种
协议，然后根据低层协议的类型字段，选择解析高一层协议的状态，然后
transition到该状态解析上层协议，最后transition到accept。包括协议：
以太网（ethernet_t），IPv4（ipv4_t）和TCP（tcp_t），具体如下：
*****************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol){
            TYPE_TCP: tcp;    //转移到tcp包头的状态
            default: accept;
        }
    }

    state tcp {
       packet.extract(hdr.tcp); //提取tcp包头
       transition accept;
    }
}


control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}


control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    register<bit<BLOOM_FILTER_BIT_WIDTH>>(BLOOM_FILTER_ENTRIES) bloom_filter_1;
    register<bit<BLOOM_FILTER_BIT_WIDTH>>(BLOOM_FILTER_ENTRIES) bloom_filter_2;
    bit<32> reg_pos_one; bit<32> reg_pos_two;
    bit<1> reg_val_one; bit<1> reg_val_two;
    bit<1> direction;

    action drop() {
        mark_to_drop(standard_metadata);
    }
    
    //使用哈希算法和布隆过滤器，哈希将在由IPv4源和目标地址，源和目标端口号以及IPv4协议类型组成的数据包5元组上计算。
    action compute_hashes(ip4Addr_t ipAddr1, ip4Addr_t ipAddr2, bit<16> port1, bit<16> port2){
       hash(reg_pos_one, HashAlgorithm.crc16, (bit<32>)0, {ipAddr1,
                                                           ipAddr2,
                                                           port1,
                                                           port2,
                                                           hdr.ipv4.protocol},
                                                           (bit<32>)BLOOM_FILTER_ENTRIES);

       hash(reg_pos_two, HashAlgorithm.crc32, (bit<32>)0, {ipAddr1,
                                                           ipAddr2,
                                                           port1,
                                                           port2,
                                                           hdr.ipv4.protocol},
                                                           (bit<32>)BLOOM_FILTER_ENTRIES);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
    
    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    //根据该动作的参数简单地设置一位方向变量
    action set_direction(bit<1> dir) {
        direction = dir;
    }


    table check_ports {
        key = {
            standard_metadata.ingress_port: exact;  //完全匹配
            standard_metadata.egress_spec: exact;
        }
        actions = {
            set_direction;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }
    
    /*
    在ipv4转发后，如果数据包进入内部网络方向设为1。否则，
    方向设为0，该操作在s1-runtime.json文件中完成。
    */
    
    apply {
        if (hdr.ipv4.isValid()){    //如果数据包具有有效的IPv4标头，首先应用该表。
            ipv4_lpm.apply();
            if (hdr.tcp.isValid()){ //如果数据包具有有效的TCP标头，接着应用check_ports表确定方向。
                direction = 0;  ///默认为0
                if (check_ports.apply().hit) {  //应用compute_hashes操作来计算两个哈希值
                    if (direction == 0) {
                        compute_hashes(hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.tcp.srcPort, hdr.tcp.dstPort);
                    }
                    else {
                        compute_hashes(hdr.ipv4.dstAddr, hdr.ipv4.srcAddr, hdr.tcp.dstPort, hdr.tcp.srcPort);
                    }
                    
                    /*如果TCP数据包正从内部网络传出并且是SYN数据包，则将两个
                    Bloom Bloom过滤器数组都设置在计算出的位位置（reg_pos_one和reg_pos_two）*/
                    
                    if (direction == 0){
                        if (hdr.tcp.syn == 1){
                            bloom_filter_1.write(reg_pos_one, 1);
                            bloom_filter_2.write(reg_pos_two, 1);
                        }
                    }
                    
                    /*否则，如果TCP数据包进入内部网络，则在计算出的位位置
                    读取两个Bloom过滤器数组，如果未设置任何数据包，则丢弃该数据包。*/
                    
                    else if (direction == 1){
                        bloom_filter_1.read(reg_val_one, reg_pos_one);
                        bloom_filter_2.read(reg_val_two, reg_pos_two);
                        if (reg_val_one != 1 || reg_val_two != 1){
                            drop();
                        }
                    }
                }
            }
        }
    }
}

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}


control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        //顺序不能乱
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
    }
}


V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
