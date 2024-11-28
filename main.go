package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"

	"github.com/deadlysurgeon/tlsmuxab/services"

	"golang.org/x/crypto/cryptobyte"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	n, err := net.Listen("tcp", ":9900")
	if err != nil {
		return err
	}
	defer n.Close()

	go acceptListener(n)

	sigWait()

	return nil
}

func acceptListener(n net.Listener) {
	for {
		conn, err := n.Accept()
		if err != nil {
			fmt.Println("Failed to accept:", err)
			continue
		}

		go handleConn(conn)
	}
}

func handleConn(conn net.Conn) {
	defer func() {
		if err := recover(); err != nil {
			fmt.Println(err)
		}
	}()
	defer func() { _ = conn.Close() }()

	bytes, err := readClientHelloHeader(conn)
	if err != nil {
		return
	}

	serverName, ok := parseClientHello(bytes)
	if !ok {
		return
	}

	fmt.Println("Dialing", serverName)

	port := services.Service(strings.Split(serverName, ".")[0]).Port()
	if port == 0 {
		return
	}

	oConn, err := net.Dial("tcp", fmt.Sprintf("%s:%d",
		"127.0.0.1", // Could have a proxy look up here.
		port,
	))
	if err != nil {
		fmt.Println(err)
		return
	}
	defer func() { _ = oConn.Close() }()

	fmt.Println("Writing Hello")
	n, err := oConn.Write(bytes)
	if err != nil {
		fmt.Println(err)
		return
	}
	if n != len(bytes) {
		fmt.Println("Didn't write all bytes")
		return
	}

	fmt.Println("Copying Connection.")
	// Forward data between client and server
	// TODO:
	// Clean up with proper logic wrapping.
	go func() { _, _ = io.Copy(conn, oConn) }() // Client to server
	_, _ = io.Copy(oConn, conn)                 // Server to client
}

var (
	// Not a handshake is returned if it is determined that the payload read is
	// not a TLS Handshake
	errNotAHandshake = errors.New("not a handshake")

	errHelloTooLarge = errors.New("client hello record to large")
)

// readClientHelloHeader returns the ClientHelloInfo message including the payload
// wrapper (5 bytes).
func readClientHelloHeader(conn net.Conn) ([]byte, error) {
	// Bit of a moot point since we still have to manually manipulate slice data
	// however it does at the very least remove magic numbers.
	const payloadSize = 5

	b := make([]byte, payloadSize)
	_, err := io.ReadFull(conn, b)
	if err != nil {
		return nil, err
	}

	if b[0] != 0x16 {
		return nil, errNotAHandshake
	}

	if b[1] != 0x03 || b[2] != 0x01 {
		return nil, errors.New("Unsupported version")
	}

	length := binary.BigEndian.Uint16(b[3:5])
	if length > 16384 {
		return nil, errHelloTooLarge
	}

	clientHello := make([]byte, length+payloadSize)
	copy(clientHello[:payloadSize], b)
	_, err = io.ReadFull(conn, clientHello[payloadSize:])
	if err != nil {
		return nil, err
	}

	return clientHello, nil
}

func sigWait() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	<-c
	signal.Stop(c)
}

// Is this ~stolen~ borrowed from crypto/tls? Maybe. Does it work? Yes.
func parseClientHello(b []byte) (string, bool) {
	s := cryptobyte.String(b)

	var ver uint16
	var random []byte
	var sessionID []byte
	if !s.Skip(5) || !s.Skip(4) || !s.ReadUint16(&ver) ||
		!s.ReadBytes(&random, 32) ||
		!readUint8LengthPrefixed(&s, &sessionID) {
		return "", false
	}

	var cs cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&cs) {
		return "", false
	}
	var cipherSuites []uint16
	secureRenegotiationSupported := false
	for !cs.Empty() {
		var suite uint16
		if !cs.ReadUint16(&suite) {
			return "", false
		}
		if suite == 0x00ff { // TODO: make constant
			secureRenegotiationSupported = true
		}
		cipherSuites = append(cipherSuites, suite)
	}
	_ = cipherSuites
	_ = secureRenegotiationSupported

	var compressionMethods []uint8
	if !readUint8LengthPrefixed(&s, &compressionMethods) {
		return "", false
	}
	if s.Empty() {
		return "", false
	}
	var exts cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&exts) || !s.Empty() {
		return "", false
	}

	var serverName string
	seenExts := make(map[uint16]bool)
	for !exts.Empty() {
		var extension uint16
		var extData cryptobyte.String
		if !exts.ReadUint16(&extension) ||
			!exts.ReadUint16LengthPrefixed(&extData) {
			return "", false
		}
		// Can't process extensions twice.
		if seenExts[extension] {
			return "", false
		}
		seenExts[extension] = true

		switch extension {
		case 0x00:
			// RFC 6066, Section 3
			var nameList cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&nameList) || nameList.Empty() {
				return "", false
			}

			for !nameList.Empty() {
				var nameType uint8
				var sn cryptobyte.String
				if !nameList.ReadUint8(&nameType) ||
					!nameList.ReadUint16LengthPrefixed(&sn) ||
					sn.Empty() {
					return "", false
				}
				if nameType != 0 {
					continue
				}
				if len(serverName) != 0 {
					// Multiple names of the same name_type are prohibited.
					return "", false
				}

				serverName = string(sn)

				// An SNI value may not include a trailing dot.
				if strings.HasSuffix(serverName, ".") {
					return "", false
				}
			}
		default:
			continue
		}
		if !extData.Empty() {
			return "", false
		}
	}
	return serverName, true
}

// []byte instead of a cryptobyte.String.
func readUint8LengthPrefixed(s *cryptobyte.String, out *[]byte) bool {
	return s.ReadUint8LengthPrefixed((*cryptobyte.String)(out))
}
