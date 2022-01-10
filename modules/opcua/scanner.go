package opcua

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"net"
	"regexp"

	"github.com/zmap/zgrab2"
)

// Flags give the command-line flags for the opcua module.
type Flags struct {
	zgrab2.BaseFlags
	UseTLS bool `long:"tls" description:"Sends probe with TLS connection. Loads TLS module command options. "`
	Hex    bool `long:"hex" description:"Store opcua value in hex. "`
	zgrab2.TLSFlags
}

// Module is the implementation of the zgrab2.Module interface.
type Module struct {
}

// Scanner is the implementation of the zgrab2.Scanner interface.
type Scanner struct {
	config *Flags
	regex  *regexp.Regexp
	probe  []byte
}

// ScanResults instances are returned by the module's Scan function.
type Results struct {
	Opcua  string         `json:"opcua,omitempty"`
	Length int            `json:"length,omitempty"`
	TLSLog *zgrab2.TLSLog `json:"tls,omitempty"`
}

// NewFlags returns a new default flags object.
func (m *Module) NewFlags() interface{} {
	return new(Flags)
}

// GetName returns the Scanner name defined in the Flags.
func (scanner *Scanner) GetName() string {
	return scanner.config.Name
}

// GetTrigger returns the Trigger defined in the Flags.
func (scanner *Scanner) GetTrigger() string {
	return scanner.config.Trigger
}

// Protocol returns the protocol identifier of the scan.
func (scanner *Scanner) Protocol() string {
	return "opcua"
}

// InitPerSender initializes the scanner for a given sender.
func (scanner *Scanner) InitPerSender(senderID int) error {
	return nil
}

// NewScanner returns a new Scanner object.
func (m *Module) NewScanner() zgrab2.Scanner {
	return new(Scanner)
}

// Validate validates the flags and returns nil on success.
func (f *Flags) Validate(args []string) error {
	return nil
}

// Description returns an overview of this module.
func (module *Module) Description() string {
	return "To check for OPCUA server"
}

// Help returns the module's help string.
func (f *Flags) Help() string {
	return ""
}

func init() {
	var tlsModule Module
	_, err := zgrab2.AddCommand("opcua", "OPC Unified Architecture", tlsModule.Description(), 4840, &tlsModule)
	if err != nil {
		log.Fatal(err)
	}
}

// Init initializes the Scanner with the command-line flags.
func (scanner *Scanner) Init(flags zgrab2.ScanFlags) error {
	f, _ := flags.(*Flags)
	scanner.config = f
	var connectPkt bytes.Buffer
	MessageType := "HEL"
	endpointUrl := "Test"

	var MessageSize = len(MessageType) + 1 + len(endpointUrl) + 28

	scanner.regex = regexp.MustCompile("ACK")
	// Based on https://reference.opcfoundation.org/v104/Core/docs/Part6/7.1.2/

	// Message Type
	connectPkt.Write([]byte(MessageType))
	// Reserved
	connectPkt.WriteByte('F')
	// message length
	msgLength := make([]byte, 4)
	binary.LittleEndian.PutUint32(msgLength, uint32(MessageSize))
	connectPkt.Write(msgLength)

	// version
	protocolVersion := make([]byte, 4)
	binary.LittleEndian.PutUint32(protocolVersion, 0)
	connectPkt.Write(protocolVersion)

	// receive Buffer size
	rvdBufSize := make([]byte, 4)
	binary.LittleEndian.PutUint32(rvdBufSize, 65535)
	connectPkt.Write(rvdBufSize)

	// send Buffer size
	sndBufSize := make([]byte, 4)
	binary.LittleEndian.PutUint32(sndBufSize, 65535)
	connectPkt.Write(sndBufSize)

	// Max Message Size
	maxMsgSize := make([]byte, 4)
	binary.LittleEndian.PutUint32(maxMsgSize, 0)
	connectPkt.Write(maxMsgSize)

	// Max Chunk Size
	maxChunkSize := make([]byte, 4)
	binary.LittleEndian.PutUint32(maxChunkSize, 0)
	connectPkt.Write(maxChunkSize)

	// endpoint Size
	endpointSize := make([]byte, 4)
	binary.LittleEndian.PutUint32(endpointSize, uint32(len(endpointUrl)))
	connectPkt.Write(endpointSize)

	// endpoint url
	connectPkt.Write([]byte(endpointUrl))

	scanner.probe = connectPkt.Bytes()
	return nil
}

var OPCUAServerResp = errors.New("No Server Found")

func (scanner *Scanner) Scan(target zgrab2.ScanTarget) (zgrab2.ScanStatus, interface{}, error) {
	var (
		conn    net.Conn
		tlsConn *zgrab2.TLSConnection
		results Results
		err     error
		readerr error
	)
	conn, err = target.Open(&scanner.config.BaseFlags)
	if err == nil {
		if scanner.config.UseTLS {
			tlsConn, err = scanner.config.TLSFlags.GetTLSConnection(conn)
			if err == nil {
				err = tlsConn.Handshake()
			}
			results.TLSLog = tlsConn.GetLog()
			conn = tlsConn
		}
	}

	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	defer conn.Close()

	var ret []byte

	_, err = conn.Write(scanner.probe)
	ret, readerr = zgrab2.ReadAvailable(conn)

	if err != nil {
		return zgrab2.TryGetScanStatus(err), &results, err
	}
	if readerr != io.EOF && readerr != nil {
		return zgrab2.TryGetScanStatus(readerr), &results, readerr
	}

	if scanner.config.Hex {
		results.Opcua = hex.EncodeToString(ret)
	} else {
		results.Opcua = string(ret)
	}
	results.Length = len(ret)

	if scanner.regex.Match(ret) {
		return zgrab2.SCAN_SUCCESS, &results, nil
	}

	return zgrab2.SCAN_PROTOCOL_ERROR, &results, OPCUAServerResp

}
