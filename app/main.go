package main

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"
)

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

	fmt.Printf("Response: %s\n", responseString)
	fmt.Printf("Hex Response:\n%s\n", hex.Dump(response))
}
