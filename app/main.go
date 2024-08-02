package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
)

const HEADER_SIZE = 12

type DNSResponse struct {
	header    DNSHeader
	questions []DNSQuestion
	answers   []DNSAnswer
}

type DNSHeader struct {
	ID      [2]byte
	FLAGS   [2]byte
	QDCOUNT [2]byte
	ANCOUNT [2]byte
	NSCOUNT [2]byte
	ARCOUNT [2]byte
}

type DNSQuestion struct {
	QNAME  []byte
	QTYPE  [2]byte
	QCLASS [2]byte
}

type DNSAnswer struct {
	NAME     []byte
	TYPE     [2]byte
	CLASS    [2]byte
	TTL      [4]byte
	RDLENGTH [2]byte
	RDATA    []byte
}

func main() {
	requestData := "00160100000100000000000003646e7306676f6f676c6503636f6d0000010001"

	requestByteData, err := hex.DecodeString(requestData)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	sendDNSRequest(string(requestByteData))
}

func sendDNSRequest(data string) {
	destinationAddr := "8.8.8.8:53"

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
	fmt.Println("sent request")
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
	responseString := string(response)

	formattedResponse := formatDNSResponse(response)

	fmt.Printf("Header ID: %d\n", int(formattedResponse.header.ID[1]))
	fmt.Printf("Response: %s\n", responseString)
	fmt.Printf("Hex Response:\n%s\n", hex.Dump(response))
}

func formatDNSResponse(response []byte) DNSResponse {
	dnsHeader := fetchDNSHeader(response[:HEADER_SIZE])

	// TODO: use question count from header to determine amount
	dnsQuestion, questionEndIdx := fetchDNSQuestion(response[HEADER_SIZE:])

	numDnsAnswer := int(binary.BigEndian.Uint16(dnsHeader.ANCOUNT[:]))
	dnsAnswers := make([]DNSAnswer, numDnsAnswer)

	answerStart := HEADER_SIZE + questionEndIdx
	answerOffset := 0
	for i := 0; i < numDnsAnswer; i++ {
		dnsAnswer, offset := fetchDNSAnswer(response[answerStart+answerOffset:])
		dnsAnswers[i] = dnsAnswer
		answerOffset += offset
	}

	// TODO: fetch authority and fetch additional records

	return DNSResponse{
		header:    dnsHeader,
		questions: []DNSQuestion{dnsQuestion},
		answers:   dnsAnswers,
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

func fetchDNSAnswer(answerBytes []byte) (DNSAnswer, int) {
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

	return DNSAnswer{
		NAME:     answerBytes[:lengthOfName],
		TYPE:     [2]byte{answerBytes[lengthOfName], answerBytes[lengthOfName+1]},
		CLASS:    [2]byte{answerBytes[lengthOfName+2], answerBytes[lengthOfName+3]},
		TTL:      [4]byte{answerBytes[lengthOfName+4], answerBytes[lengthOfName+5], answerBytes[lengthOfName+6], answerBytes[lengthOfName+7]},
		RDLENGTH: RDLENGTH,
		RDATA:    answerBytes[lengthOfName+10 : lengthOfName+10+length],
	}, lengthOfName + 10 + length
}
