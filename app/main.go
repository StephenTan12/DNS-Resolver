package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

const HEADER_SIZE = 12
const DNS_ID = 22
const ROOT_NAME_SERVER_IP = "198.41.0.4:53"

type DNSPacket struct {
	header      DNSHeader
	questions   []DNSQuestion
	answers     []DNSResourceRecord
	authorities []DNSResourceRecord
	additionals []DNSResourceRecord
}

func (p DNSPacket) String() string {
	responseString := p.header.String()

	for _, question := range p.questions {
		responseString += question.String()
	}

	for _, answer := range p.answers {
		responseString += answer.String()
	}

	for _, authority := range p.authorities {
		responseString += authority.String()
	}

	for _, additional := range p.additionals {
		responseString += additional.String()
	}

	return responseString
}

type DNSHeader struct {
	ID      [2]byte
	FLAGS   [2]byte
	QDCOUNT [2]byte
	ANCOUNT [2]byte
	NSCOUNT [2]byte
	ARCOUNT [2]byte
}

func (h DNSHeader) String() string {
	return fmt.Sprintf("%x%x%x%x%x%x", h.ID, h.FLAGS, h.QDCOUNT, h.ANCOUNT, h.NSCOUNT, h.ARCOUNT)
}

type DNSQuestion struct {
	QNAME  []byte
	QTYPE  [2]byte
	QCLASS [2]byte
}

func (q DNSQuestion) String() string {
	return fmt.Sprintf("%x%x%x", q.QNAME, q.QTYPE, q.QCLASS)
}

type DNSResourceRecord struct {
	NAME     []byte
	TYPE     [2]byte
	CLASS    [2]byte
	TTL      [4]byte
	RDLENGTH [2]byte
	RDATA    []byte
}

func (r DNSResourceRecord) String() string {
	return fmt.Sprintf("%x%x%x%x%x%x", r.NAME, r.TYPE, r.CLASS, r.TTL, r.RDLENGTH, r.RDATA)
}

func main() {
	destinationAddr := ROOT_NAME_SERVER_IP
	requestDomain := "reddit.com"
	setRecursion := true

	var dnsQueryPacket DNSPacket

	if setRecursion {
		dnsQueryPacket = createDNSQuery(requestDomain, 0)
	} else {
		dnsQueryPacket = createDNSQuery(requestDomain, 1)
	}

	requestByteData, err := hex.DecodeString(dnsQueryPacket.String())
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	handleDNSQuery(requestByteData, destinationAddr)
}

func handleDNSQuery(byteData []byte, destinationAddr string) {
	returnPacket := sendDNSQuery(string(byteData), destinationAddr)

	for {
		if len(returnPacket.answers) != 0 {
			fmt.Println(formatIPAddrFromRDATA(returnPacket.answers[0].RDATA, -1))
			break
		}

		destinationAddr = ""

		var rrAdditional DNSResourceRecord

		for _, additional := range returnPacket.additionals {
			rrType := binary.BigEndian.Uint16(additional.TYPE[:])
			if rrType != 1 {
				continue
			}
			rrAdditional = additional
			break
		}

		if len(rrAdditional.NAME) == 0 {
			fmt.Println("No additional resource records")
			os.Exit(1)
		}

		destinationAddr = formatIPAddrFromRDATA(rrAdditional.RDATA, 53)
		returnPacket = sendDNSQuery(string(byteData), destinationAddr)
	}
}

func createDNSQuery(requestIPDomain string, setRecursion int) DNSPacket {
	dnsHeader := DNSHeader{
		ID:      [2]byte{0, DNS_ID},
		FLAGS:   [2]byte{byte(setRecursion), 0},
		QDCOUNT: [2]byte{0, 1},
		ANCOUNT: [2]byte{0, 0},
		NSCOUNT: [2]byte{0, 0},
		ARCOUNT: [2]byte{0, 0},
	}

	dnsQuestion := DNSQuestion{
		QNAME:  encodeDomainName(requestIPDomain),
		QTYPE:  [2]byte{0, 1},
		QCLASS: [2]byte{0, 1},
	}

	return DNSPacket{
		header:    dnsHeader,
		questions: []DNSQuestion{dnsQuestion},
	}
}

func sendDNSQuery(data string, destinationAddr string) DNSPacket {

	udpAddr, err := net.ResolveUDPAddr("udp", destinationAddr)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	udpConn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer udpConn.Close()

	_, err = udpConn.Write([]byte(data))
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	buf := make([]byte, 512)

	size, source, err := udpConn.ReadFromUDP(buf)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Printf("Receive %d bytes from %s\n", size, source)

	response := buf[:size]

	formattedResponse := formatDNSResponse(response)

	fmt.Printf("Header ID: %d\n", int(formattedResponse.header.ID[1]))
	fmt.Printf("Answer Count: %d\n", len(formattedResponse.answers))
	fmt.Printf("Authority Count: %d\n", len(formattedResponse.authorities))
	fmt.Printf("Additional Count: %d\n\n\n", len(formattedResponse.additionals))

	return formattedResponse
}

func formatDNSResponse(response []byte) DNSPacket {
	dnsHeader := fetchDNSHeader(response[:HEADER_SIZE])

	// TODO: use question count from header to determine amount
	dnsQuestion, questionEndIdx := fetchDNSQuestion(response[HEADER_SIZE:])

	resourceRecordsOffset := HEADER_SIZE + questionEndIdx

	numDnsAnswer := int(binary.BigEndian.Uint16(dnsHeader.ANCOUNT[:]))
	numDnsAuthorities := int(binary.BigEndian.Uint16(dnsHeader.NSCOUNT[:]))
	numDnsAdditionals := int(binary.BigEndian.Uint16(dnsHeader.ARCOUNT[:]))

	dnsAnswers, dnsAnswersOffset := fetchDNSResourceRecords(response, numDnsAnswer, resourceRecordsOffset)
	resourceRecordsOffset += dnsAnswersOffset

	dnsAuthorities, dnsAuthoritiesCount := fetchDNSResourceRecords(response, numDnsAuthorities, resourceRecordsOffset)
	resourceRecordsOffset += dnsAuthoritiesCount

	dnsAdditionals, _ := fetchDNSResourceRecords(response, numDnsAdditionals, resourceRecordsOffset)

	return DNSPacket{
		header:      dnsHeader,
		questions:   []DNSQuestion{dnsQuestion},
		answers:     dnsAnswers,
		authorities: dnsAuthorities,
		additionals: dnsAdditionals,
	}
}

func fetchDNSHeader(headerBytes []byte) DNSHeader {
	return DNSHeader{
		ID:      [2]byte{headerBytes[0], headerBytes[1]},
		FLAGS:   [2]byte{headerBytes[2], headerBytes[3]},
		QDCOUNT: [2]byte{headerBytes[4], headerBytes[5]},
		ANCOUNT: [2]byte{headerBytes[6], headerBytes[7]},
		NSCOUNT: [2]byte{headerBytes[8], headerBytes[9]},
		ARCOUNT: [2]byte{headerBytes[10], headerBytes[11]},
	}
}

func fetchDNSQuestion(questionBytes []byte) (DNSQuestion, int) {
	lengthOfQName := 0
	for {
		if questionBytes[lengthOfQName] == 0x00 {
			break
		}
		lengthOfQName += 1
	}
	lengthOfQName += 1

	return DNSQuestion{
		QNAME:  questionBytes[:lengthOfQName],
		QTYPE:  [2]byte{questionBytes[lengthOfQName], questionBytes[lengthOfQName+1]},
		QCLASS: [2]byte{questionBytes[lengthOfQName+2], questionBytes[lengthOfQName+3]},
	}, lengthOfQName + 4
}

func fetchDNSResourceRecords(response []byte, resourceRecordCount int, offset int) ([]DNSResourceRecord, int) {
	dnsResourceRecords := make([]DNSResourceRecord, resourceRecordCount)
	resourceRecordOffset := 0

	for i := 0; i < resourceRecordCount; i++ {
		dnsResourceRecord, offset := fetchDNSResourceRecord(response[offset+resourceRecordOffset:])
		dnsResourceRecords[i] = dnsResourceRecord
		resourceRecordOffset += offset
	}

	return dnsResourceRecords, resourceRecordOffset
}

func fetchDNSResourceRecord(answerBytes []byte) (DNSResourceRecord, int) {
	lengthOfName := 2

	if binary.BigEndian.Uint16(answerBytes[:2])>>14 != 0x3 {
		lengthOfName = 0
		for {
			if answerBytes[lengthOfName] == 0x00 {
				break
			}
			lengthOfName += 1
		}
		lengthOfName += 1
	}

	RDLENGTH := [2]byte{answerBytes[lengthOfName+8], answerBytes[lengthOfName+9]}
	length := int(binary.BigEndian.Uint16(RDLENGTH[:]))

	return DNSResourceRecord{
		NAME:     answerBytes[:lengthOfName],
		TYPE:     [2]byte{answerBytes[lengthOfName], answerBytes[lengthOfName+1]},
		CLASS:    [2]byte{answerBytes[lengthOfName+2], answerBytes[lengthOfName+3]},
		TTL:      [4]byte{answerBytes[lengthOfName+4], answerBytes[lengthOfName+5], answerBytes[lengthOfName+6], answerBytes[lengthOfName+7]},
		RDLENGTH: RDLENGTH,
		RDATA:    answerBytes[lengthOfName+10 : lengthOfName+10+length],
	}, lengthOfName + 10 + length
}

func encodeDomainName(domain string) []byte {
	domains := strings.Split(domain, ".")

	size := len(domains) + 1
	for _, label := range domains {
		size += len(label)
	}

	buf := make([]byte, size)

	bufIndex := 0

	for _, label := range domains {
		buf[bufIndex] = uint8(len(label))
		bufIndex += 1

		for i, char := range label {
			buf[i+bufIndex] = uint8(char)
		}
		bufIndex += len(label)
	}

	buf[bufIndex] = 0

	return buf
}

func formatIPAddrFromRDATA(RDATA []byte, port int) string {
	ipAddr := ""
	for _, segment := range RDATA {
		ipAddr += strconv.Itoa(int(segment)) + "."
	}

	if port == -1 {
		return ipAddr[:len(ipAddr)-1]
	}
	return ipAddr[:len(ipAddr)-1] + ":" + strconv.Itoa(port)
}
