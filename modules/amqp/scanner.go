package amqp

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"net"
	"regexp"

	"github.com/zmap/zgrab2"
)

// Flags give the command-line flags for the amqp module.
type Flags struct {
	zgrab2.BaseFlags
	UseTLS bool `long:"tls" description:"Sends probe with TLS connection. Loads TLS module command options. "`
	Hex    bool `long:"hex" description:"Store amqp value in hex. "`
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
	Amqp   string `json:"amqp,omitempty"`
	Length int    `json:"length,omitempty"`
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
	return "amqp"
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
	return "To check for AMQP server"
}

// Help returns the module's help string.
func (f *Flags) Help() string {
	return ""
}

func init() {
	var tlsModule Module
	_, err := zgrab2.AddCommand("amqp", "Advanced Message Queuing Protocol", tlsModule.Description(), 5672, &tlsModule)
	if err != nil {
		log.Fatal(err)
	}
}

// Init initializes the Scanner with the command-line flags.
func (scanner *Scanner) Init(flags zgrab2.ScanFlags) error {
	f, _ := flags.(*Flags)
	scanner.config = f
	var connectPkt bytes.Buffer
	protocolName := "AMQP"

	scanner.regex = regexp.MustCompile(protocolName)
	// AMQP
	connectPkt.Write([]byte(protocolName))

	// Protocol ID major
	connectPkt.WriteByte(0)
	// Protocol ID minor
	connectPkt.WriteByte(0)

	// Version ID major
	connectPkt.WriteByte(9)
	// Version ID minor
	connectPkt.WriteByte(1)

	scanner.probe = connectPkt.Bytes()
	return nil
}

var AMQPServerResp = errors.New("No Server Found")

func (scanner *Scanner) Scan(target zgrab2.ScanTarget) (zgrab2.ScanStatus, interface{}, error) {
	var (
		conn    net.Conn
		tlsConn *zgrab2.TLSConnection
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
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	if readerr != io.EOF && readerr != nil {
		return zgrab2.TryGetScanStatus(readerr), nil, readerr
	}
	var results Results
	if scanner.config.Hex {
		results = Results{Amqp: hex.EncodeToString(ret), Length: len(ret)}
	} else {
		results = Results{Amqp: string(ret), Length: len(ret)}
	}

	if scanner.regex.Match(ret) {
		return zgrab2.SCAN_SUCCESS, &results, nil
	}

	return zgrab2.SCAN_PROTOCOL_ERROR, &results, AMQPServerResp

}
