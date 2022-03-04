package mqtt

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"net"

	"github.com/zmap/zgrab2"
)

// Flags give the command-line flags for the mqtt module.
type Flags struct {
	zgrab2.BaseFlags
	UseTLS bool `long:"tls" description:"Sends probe with TLS connection. Loads TLS module command options. "`
	Hex    bool `long:"hex" description:"Store mqtt value in hex. "`
	zgrab2.TLSFlags
}

// Module is the implementation of the zgrab2.Module interface.
type Module struct {
}

// Scanner is the implementation of the zgrab2.Scanner interface.
type Scanner struct {
	config *Flags
	probe  []byte
}

// ScanResults instances are returned by the module's Scan function.
type Results struct {
	Mqtt   string         `json:"mqtt,omitempty"`
	Length int            `json:"length,omitempty"`
	TLSLog *zgrab2.TLSLog `json:"tls,omitempty"`
}

// RegisterModule is called by modules/mqtt.go to register the scanner.
func RegisterModule() {
	var module Module
	_, err := zgrab2.AddCommand("mqtt", "MQTT", module.Description(), 1883, &module)
	if err != nil {
		log.Fatal(err)
	}
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
	return "mqtt"
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
	return "Try to connect to MQTT server"
}

// Help returns the module's help string.
func (f *Flags) Help() string {
	return ""
}

func init() {
	var tlsModule Module
	_, err := zgrab2.AddCommand("mqtt", "MQTT", tlsModule.Description(), 1883, &tlsModule)
	if err != nil {
		log.Fatal(err)
	}
}

// Init initializes the Scanner with the command-line flags.
func (scanner *Scanner) Init(flags zgrab2.ScanFlags) error {
	f, _ := flags.(*Flags)
	scanner.config = f
	var connectPkt bytes.Buffer
	protocolName := "MQTT"
	clientID := "Test"

	// Header Flag
	connectPkt.WriteByte(1<<4 | 0<<3 | 0<<1)
	// protocol length
	connectPkt.WriteByte(16)

	// MQTT version details
	msgLength := make([]byte, 2)
	binary.BigEndian.PutUint16(msgLength, 4)
	connectPkt.Write(msgLength)
	connectPkt.Write([]byte(protocolName))
	connectPkt.WriteByte(4)

	// connect flag
	connectPkt.WriteByte(1 << 1)

	// Keep ALive
	keepAlive := make([]byte, 2)
	binary.BigEndian.PutUint16(keepAlive, 30)
	connectPkt.Write(keepAlive)

	// client ID
	// MQTT version details
	clientIDLength := make([]byte, 2)
	binary.BigEndian.PutUint16(clientIDLength, 4)
	connectPkt.Write(clientIDLength)
	connectPkt.Write([]byte(clientID))

	scanner.probe = connectPkt.Bytes()
	return nil
}

var NoMQTTconnection = errors.New("Connection not possible")

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
		results.Mqtt = hex.EncodeToString(ret)
	} else {
		results.Mqtt = string(ret)
	}
	results.Length = len(ret)
	// CONNACK
	if len(ret) == 4 {
		if ((ret[0] & 0xF0) == 0x20) && (ret[1] == 0x02) {
			return zgrab2.SCAN_SUCCESS, &results, nil
		}
	}
	// DISCONNECT
	if len(ret) == 2 {
		if ((ret[0] & 0xF0) == 0xE0) && (ret[1] == 0x00) {
			return zgrab2.SCAN_SUCCESS, &results, nil
		}
	}

	return zgrab2.SCAN_PROTOCOL_ERROR, &results, NoMQTTconnection

}
