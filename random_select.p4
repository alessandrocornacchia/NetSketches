/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#define MAX_SUPPORTED_PATH_LEN 5

// NOTE: new type added here
const bit<16> TYPE_IPV4 = 0x800;
const bit<8> TYPE_SKETCH = 0x90;
const int FRAGMENT_TABLE_SIZE = 1024;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<16> label_t;
typedef bit<3> pathLen_t;   // 3-bit so that sketch_t is byte-aligned
typedef bit<MAX_SUPPORTED_PATH_LEN> nmi_t;


header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header sketch_t {
    nmi_t NMI; // network monitor information
    pathLen_t pos;
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

/*
* - bit<32> comb_index : exact match index in sketch_fragment_table
* - bit<4> basePtr;    : pointer to the beginning of subtable for a certain
                         path length and a given subset of K fragments
* - bit<4> numComb;    : size of the subtable referenced by basePtr
*/
struct metadata {
    bit<32> comb_index;
    bit<4> basePtr;
    bit<4> numComb;
}

// NOTE: Added new header type to headers struct
struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    sketch_t     sketch;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

// TODO: Update the parser to parse the myTunnel header as well
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
            TYPE_IPV4 : parse_ipv4;
            default : accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            TYPE_SKETCH : parse_sketch;
            default : accept;
        }
    }

    state parse_sketch {
        packet.extract(hdr.sketch);
        transition accept;
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port, bit<4> basePtr, bit<4> numComb) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;

        meta.basePtr = basePtr;
        meta.numComb = numComb;

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

    action select_fragments(nmi_t nmi) {
        //  setValid() has to be called BEFORE modifying fields,
        // otherwise no effect (it's like the header does not exists)
        hdr.sketch.setValid();
        hdr.sketch.NMI = nmi;
        hdr.sketch.pos = 0;
        hdr.ipv4.protocol = TYPE_SKETCH;
        hdr.ipv4.totalLen = hdr.ipv4.totalLen + 1;
    }

    // Table to handle all N choose K possible groups
    table sketch_fragment_table {
        key = {
            meta.comb_index : exact;
        }
        actions = {
            select_fragments;
            NoAction;
        }
        size = FRAGMENT_TABLE_SIZE;
        default_action = NoAction;
    }

    apply {
        if (hdr.ipv4.isValid()) {

            if (ipv4_lpm.apply().hit) {
                if (standard_metadata.ingress_port == 1) {
                    // act as ingress switch (only for packets entering the network i.e. port 1)
                    hash(meta.comb_index,
                        HashAlgorithm.crc16,
                        meta.basePtr,
                        {hdr.ipv4.dstAddr, hdr.ipv4.srcAddr},
                        meta.numComb);
                    sketch_fragment_table.apply();
                }
                // if there is already sketch header act as a transit switch,
                // otherwise act as ingress switch adding sketch header
                if(hdr.sketch.isValid()) {
                    bit<1> should_count = (bit<1>)((hdr.sketch.NMI >> (MAX_SUPPORTED_PATH_LEN - hdr.sketch.pos - 1)) & (nmi_t)1);
                    log_msg("Should count pkt? : {}", {should_count});
                    hdr.sketch.pos = hdr.sketch.pos + 1;
                }
            }
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

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

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.sketch);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
