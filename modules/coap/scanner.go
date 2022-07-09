package coap

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"net"

	"github.com/pion/dtls/v2"
	"github.com/pion/dtls/v2/pkg/crypto/selfsign"
	"github.com/zmap/zgrab2"
)

// Flags give the command-line flags for the coap module.
type Flags struct {
	zgrab2.BaseFlags
	zgrab2.UDPFlags
	UriPath string `long:"uri-path" default:"/.well-known/core" description:"URI path of the coap server. Use triple slashes to escape, for example \\\\\\n is literal \\n. NOTE: Implementation Pending"`
	UseDTLS bool   `long:"dtls" description:"Sends probe with DTLS connection. Loads DTLS module command options. "`
	Hex     bool   `long:"hex" description:"Store mqtt value in hex. "`
}

// Module is the implementation of the zgrab2.Module interface.
type Module struct {
}

// Scanner is the implementation of the zgrab2.Scanner interface.
type Scanner struct {
	config *Flags
	// regex  *regexp.Regexp
	probe []byte
}

// ScanResults instances are returned by the module's Scan function.
type Results struct {
	Coap               string `json:"coap,omitempty"`
	Length             int    `json:"length,omitempty"`
	PeerCertificate    string `json:"PeerCertificate,omitempty"`
	IdentityHint       string `json:"IdentityHint,omitempty"`
	NegotiatedProtocol string `json:"NegotiatedProtocol,omitempty"`
	SessionID          string `json:"SessionID,omitempty"`
}

// RegisterModule registers the zgrab2 module.
func init() {
	var module Module
	_, err := zgrab2.AddCommand("coap", "Constrained Application Protocol", module.Description(), 5683, &module)
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
	return "coap"
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
	return "To check for coap server"
}

// Help returns the module's help string.
func (f *Flags) Help() string {
	return ""
}

// Init initializes the Scanner with the command-line flags.
func (scanner *Scanner) Init(flags zgrab2.ScanFlags) error {
	f, _ := flags.(*Flags)
	scanner.config = f
	var connectPkt bytes.Buffer

	var (
		coapHeader  byte
		code_GET    byte
		token_value byte
	)
	coapHeader = 0x41
	code_GET = 0x01
	token_value = 0x01
	// Header Flag
	connectPkt.WriteByte(coapHeader)
	// Code
	connectPkt.WriteByte(code_GET)

	// Message ID
	msgID := make([]byte, 2)
	binary.BigEndian.PutUint16(msgID, 61000)
	connectPkt.Write(msgID)
	connectPkt.WriteByte(token_value)
	// TODO: pending implementation of CoAP Option field
	// connectPkt.Write([]byte{0xBB})
	// connectPkt.Write([]byte(scanner.config.UriPath))

	connectPkt.Write([]byte{0xBB, 0x2E, 0x77, 0x65, 0x6C, 0x6C, 0x2D, 0x6B, 0x6E, 0x6F, 0x77, 0x6E, 0x04, 0x63, 0x6F, 0x72, 0x65}) // corresponding to /.well-known/core

	scanner.probe = connectPkt.Bytes()
	return nil
}

var NoConnection = errors.New("Connection not possible")

func (scanner *Scanner) Scan(target zgrab2.ScanTarget) (zgrab2.ScanStatus, interface{}, error) {
	var (
		conn    net.Conn
		config  *dtls.Config
		results Results
		port    uint
		err     error
		readerr error
	)

	// If the port is supplied in ScanTarget, let that override the cmdline option
	if target.Port != nil {
		port = *target.Port
	} else {
		port = scanner.config.BaseFlags.Port
	}

	if scanner.config.UseDTLS {

		addr := &net.UDPAddr{IP: net.ParseIP(target.Host()), Port: int(port)}
		certificate, err := selfsign.GenerateSelfSigned()
		if err != nil {
			// log.Fatalln(err)
			return zgrab2.TryGetScanStatus(err), nil, err
		}
		// Prepare the configuration of the DTLS connection
		config = &dtls.Config{
			Certificates:         []tls.Certificate{certificate},
			InsecureSkipVerify:   true,
			ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
		}

		// Connect to a DTLS server
		ctx, cancel := context.WithTimeout(context.Background(), scanner.config.BaseFlags.Timeout)
		defer cancel()
		conn, err = dtls.DialWithContext(ctx, "udp", addr, config)
		if err != nil {
			return zgrab2.SCAN_UNKNOWN_ERROR, nil, err
		}
	} else {
		conn, err = target.OpenUDP(&scanner.config.BaseFlags, &scanner.config.UDPFlags)
		if err != nil {
			return zgrab2.TryGetScanStatus(err), nil, err
		}
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
		results.Coap = hex.EncodeToString(ret)
	} else {
		results.Coap = string(ret)
	}
	results.Length = len(ret)

	if scanner.config.UseDTLS {
		dtlsConn := conn.(*dtls.Conn)
		results.PeerCertificate = hex.EncodeToString(dtlsConn.ConnectionState().PeerCertificates[0])
		results.SessionID = hex.EncodeToString(dtlsConn.ConnectionState().SessionID)
		results.IdentityHint = hex.EncodeToString(dtlsConn.ConnectionState().IdentityHint)
		results.NegotiatedProtocol = dtlsConn.ConnectionState().NegotiatedProtocol
	}

	if len(ret) >= 5 {
		if ((ret[0] & 0xC0) == 0x40) && (binary.BigEndian.Uint16([]byte{ret[2], ret[3]}) == 61000) && ret[4] == 0x01 {
			return zgrab2.SCAN_SUCCESS, &results, nil
		}
	}
	return zgrab2.SCAN_UNKNOWN_ERROR, &results, NoConnection

}

// // Implementation based on https://github.com/plgd-dev/go-coap
// func (scanner *Scanner) Scan(target zgrab2.ScanTarget) (zgrab2.ScanStatus, interface{}, error) {
// 	var (
// 		conn    *client.ClientConn
// 		config  *piondtls.Config
// 		results Results
// 		port    uint
// 		err     error
// 		logs    *logging.DefaultLoggerFactory
// 	)

// 	logs = logging.NewDefaultLoggerFactory()

// 	logs.DefaultLogLevel.Set(logging.LogLevelDebug)

// 	// If the port is supplied in ScanTarget, let that override the cmdline option
// 	if target.Port != nil {
// 		port = *target.Port
// 	} else {
// 		port = scanner.config.BaseFlags.Port
// 	}
// 	address := net.JoinHostPort(target.Host(), fmt.Sprintf("%d", port))

// 	if scanner.config.UseDTLS {
// 		certificate, err := selfsign.GenerateSelfSigned()
// 		if err != nil {
// 			// log.Fatalln(err)
// 			return zgrab2.TryGetScanStatus(err), nil, err
// 		}
// 		// Prepare the configuration of the DTLS connection
// 		config = &piondtls.Config{
// 			Certificates:         []tls.Certificate{certificate},
// 			InsecureSkipVerify:   true,
// 			ExtendedMasterSecret: piondtls.RequireExtendedMasterSecret,
// 			LoggerFactory:        logs,
// 		}
// 		conn, err = DLTS.Dial(address, config)
// 		if err != nil {
// 			// log.Fatalf("Error dialing: %v", err)
// 			return zgrab2.SCAN_UNKNOWN_ERROR, nil, err
// 		}
// 	} else {
// 		conn, err = udp.Dial(address)
// 		if err != nil {
// 			// log.Fatalf("Error dialing: %v", err)
// 			return zgrab2.TryGetScanStatus(err), nil, err
// 		}
// 	}

// 	defer conn.Close()

// 	path := scanner.config.UriPath

// 	ctx, cancel := context.WithTimeout(context.Background(), scanner.config.BaseFlags.Timeout)
// 	defer cancel()
// 	resp, err := conn.Get(ctx, path)
// 	if err != nil {
// 		return zgrab2.TryGetScanStatus(err), nil, err
// 	}

// 	if resp != nil {
// 		res, err := resp.ReadBody()
// 		results.Coap = ""
// 		if err == nil {
// 			results.Coap = resp.String() + string(res)

// 		}
// 		results.Length = len(res)
// 	}

// 	fmt.Printf("logs: %v\n", logs)

// 	return zgrab2.SCAN_SUCCESS, &results, nil

// }

/* EOF */
