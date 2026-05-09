package main

import "core:encoding/endian"
import "core:log"
import "core:net"
import "core:strings"

Qtype :: enum u16 {
	A = 1,
	NS,
	MD,
	MF,
	CNAME,
	SOA,
	MB,
	MG,
	MR,
	NULL,
	WKS,
	PTR,
	HINFO,
	MINFO,
	MX,
	TXT,
}

Dns_Header :: struct {
	id:      u16,
	qr:      bool,
	opcode:  u8,
	aa:      bool,
	tc:      bool, //trunc
	rd:      bool, //recursion desired
	ra:      bool,
	z:       u8, //no initialize this, auto to 0 is correct
	rcode:   Rcode,
	qdcount: u16,
	ancount: u16,
	nscount: u16,
	arcount: u16,
}

Dns_Question :: struct {
	qname:  []byte,
	qtype:  Qtype,
	qclass: u16,
}

Rcode :: enum u8 {
	OK,
	FormatErr,
	ServerFailure,
	NameError,
	NotImplemented,
	Refused,
}

Dns_Query :: struct {
	header:   Dns_Header,
	question: Dns_Question,
}


// 1  1  1  1  1  1
// 0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                      ID                       |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    QDCOUNT                    |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    ANCOUNT                    |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    NSCOUNT                    |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    ARCOUNT                    |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
encode_dns_query :: proc(q: Dns_Query) -> []byte {
	// log.infof("%v", q)
	b: [dynamic]byte

	// ok first fill header fucker
	id_b: [2]byte
	endian.unchecked_put_u16be(id_b[:], q.header.id)
	append(&b, ..id_b[:])


	// TODO look into [bit_set]
	flags: u16
	// |= makes sure dont rewrite whole shenanigans

	if q.header.qr {flags |= 1 << 15}
	flags |= u16(q.header.opcode & 0xF) << 11
	if q.header.aa {flags |= 1 << 10}
	if q.header.tc {flags |= 1 << 9}
	if q.header.rd {flags |= 1 << 8}
	if q.header.ra {flags |= 1 << 7}
	flags |= u16(u8(q.header.rcode) & 0xF)

	flag_bytes: [2]byte
	endian.unchecked_put_u16be(flag_bytes[:], flags)
	append(&b, ..flag_bytes[:])

	// count shit
	count_b: [2]byte
	endian.unchecked_put_u16be(count_b[:], q.header.qdcount)
	append(&b, ..count_b[:])
	endian.unchecked_put_u16be(count_b[:], q.header.ancount)
	append(&b, ..count_b[:])
	endian.unchecked_put_u16be(count_b[:], q.header.nscount)
	append(&b, ..count_b[:])
	endian.unchecked_put_u16be(count_b[:], q.header.arcount)
	append(&b, ..count_b[:])

	// then the question
	labels := strings.split(string(q.question.qname), ".")
	for label in labels {
		append(&b, byte(len(label)))
		append(&b, ..transmute([]byte)label)
	}
	append(&b, 0x00) // null

	qtype_bytes: [2]byte
	endian.unchecked_put_u16be(qtype_bytes[:], u16(q.question.qtype))
	append(&b, ..qtype_bytes[:])

	qclass_bytes: [2]byte
	endian.unchecked_put_u16be(qclass_bytes[:], q.question.qclass)
	append(&b, ..qclass_bytes[:])

	return b[:]
}


decode_dns_query :: proc(raw: []byte) -> Dns_Query {
	q: Dns_Query
	return q
}


// 	  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//    |                                               |
//    /                                               /
//    /                      NAME                     /
//    |                                               |
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//    |                      TYPE                     |
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//    |                     CLASS                     |
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//    |                      TTL                      |
//    |                                               |
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//    |                   RDLENGTH                    |
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
//    /                     RDATA                     /
//    /                                               /
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
decode_dns_response :: proc(b: []byte) -> Dns_Response {
	r: Dns_Response
	offset := 12

	if b[offset] == 0xC0 {
		offset += 2 // compression ptr is always exactly 2 bytes
	} else {
		for b[offset] != 0 {
			offset += 1
		}
		offset += 1 // null shit
	}
	offset += 4 // qtype (2 oct) + qclass (2 oct)

	if b[offset] == 0xC0 {
		offset += 2
	} else {
		for b[offset] != 0 {
			offset += 1
		}
		offset += 1
	}

	offsetPtr := &offset

	// type 2 octetts
	// class 2 octets
	// ttl 32bit integer, 4 octets
	// rdlen 2
	// rdata ThaT OF rdlen

	read_and_offset :: proc(b: []byte, size: int, offsetPtr: ^int) -> []byte {
		val := b[offsetPtr^:offsetPtr^ + size]; offsetPtr^ += size
		return val
	}

	type := read_and_offset(b, 2, offsetPtr)
	class := read_and_offset(b, 2, offsetPtr)
	ttl := read_and_offset(b, 4, offsetPtr)
	rdlen := read_and_offset(b, 2, offsetPtr)
	rdlen_val := int(endian.unchecked_get_u16be(rdlen))
	rdata := read_and_offset(b, rdlen_val, offsetPtr)


	r.type = endian.unchecked_get_u16be(type)
	r.class = endian.unchecked_get_u16be(class)
	r.ttl = endian.unchecked_get_u32be(ttl)
	r.rdlen = endian.unchecked_get_u16be(rdlen)
	r.rdata = rdata
	return r
}


Dns_Response :: struct {
	type:  u16,
	class: u16,
	ttl:   u32,
	rdlen: u16,
	rdata: []byte,
}

Worker_Interface :: struct {
	work: proc(nTasks: []u32) -> u32,
}


// ok instead of cmd tool
// this one should act as a udp 53 server,
// that forwards dns queries to 8888:53 dns server and returns answer back
// basic premise is, nslookup and dig to this server should work as with 8888, if that shi works
// job is done
main :: proc() {
	logger := log.create_console_logger()
	context.logger = logger
	log.info("main...")
	socket, serr := net.make_unbound_udp_socket(.IP4)
	if serr != nil {
		log.fatalf("socket create err: %v", serr)
	}
	log.infof("udp socket created")

	bind_err := net.bind(socket, net.Endpoint{net.IP4_Address{127, 0, 0, 1}, 53})
	if bind_err != nil {
		log.fatalf("bind_err: %v", bind_err)
	}

	query_buf: [512]byte
	resp_buf: [512]byte

	for {
		q_bytes_read, from, recverr := net.recv_udp(socket, query_buf[:])
		if recverr != nil {
			log.fatalf("recv error: %v", recverr)
		}
		log.infof("%d q_bytes_read from %v", q_bytes_read, from)

		up_sock, _ := net.make_unbound_udp_socket(.IP4)
		net.bind(up_sock, net.Endpoint{net.IP4_Address{0, 0, 0, 0}, 0})

		net.send_udp(
			up_sock,
			query_buf[:q_bytes_read],
			net.Endpoint{address = net.IP4_Address{8, 8, 8, 8}, port = 53},
		)

		resp_bytes_read, _, _ := net.recv_udp(up_sock, resp_buf[:])
		log.infof("%d bytes from upstream", resp_bytes_read)

		net.close(up_sock)

		net.send_udp(socket, resp_buf[:resp_bytes_read], from)
		log.infof("forwarded response back to client")
	}
}
