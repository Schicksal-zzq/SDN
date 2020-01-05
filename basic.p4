#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;

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

struct metadata {
    /* empty */
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
}

/****************************************************************
parser是一个有限状态机。从 start 状态开始，每一个状态便解析一种
协议，然后根据低层协议的类型字段，选择解析高一层协议的状态，然后
transition到该状态解析上层协议，最后transition到accept。具体如下：
*****************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;  //转移到以太网包头的状态
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);   //提取以太网包头
        transition select(hdr.ethernet.etherType) {   //由协议转移到相关状态
            TYPE_IPV4: parse_ipv4;  //ipv4
            default: accept;    //默认是接受，进入下一步处理
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);   //提取ipv4包头
        transition accept;  //转移到接受状态
    }

}

/****************************************************************
输入校验和验证，由高度抽象的内置函数直接完成
*****************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}

/****************************************************************
输入处理，在Ingress中，我们要实现一个转发功能，因此需要定义一个用于转发的流表：
*****************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop(standard_metadata);    //内置函数，将当前数据包标记为即将丢弃的数据包
    }
    
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        //转发步骤
        standard_metadata.egress_spec = port;   //设置下一跳的出口端口
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;    //更新源地址（到达下一跳）
        hdr.ethernet.dstAddr = dstAddr; //更新目标地址
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;    //ttl减1
    }
    
    table ipv4_lpm {
        key = { //流表拥有的匹配域
            hdr.ipv4.dstAddr: lpm;  //匹配字段是数据包头的ip目的地址
        }                           //lpm 说明匹配的模式是 Longest Prefix Match，即最长前缀匹配 
                                    //还有 exact(完全匹配)， ternary(三元匹配)
        actions = { //定义控制平面添加流表项时，可选的动作。
            ipv4_forward;   //转发动作
            drop;   //丢弃
            NoAction;   //空动作
        }
        size = 1024;    //流表可以容纳多少流表项
        default_action = drop();    //table miss 是丢弃动作
    }
    
    apply { //上面只是一些定义，真正的数据包处理逻辑在这里。
        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
        }
    }
}

/****************************************************************
输出处理，与Ingress处理过程类似
*****************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/****************************************************************
输出校验和检验，由高度抽象的内置函数直接完成
*****************************************************************/

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

/****************************************************************
Deparser 数据包重组
*****************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
    }
}

/****************************************************************
将上述代码中定义的各个模块组装起来，有点像C/C++中的main函数
*****************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
