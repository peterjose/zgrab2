package dtls

import (
	"context"
	"crypto/tls"
	"log"
	"net"
	"time"

	dtls "github.com/pion/dtls/v2"
	"github.com/pion/dtls/v2/pkg/crypto/selfsign"
	"github.com/pion/logging"

	"github.com/zmap/zgrab2"
)

// Flags give the command-line flags for the dtls module.
type Flags struct {
	zgrab2.BaseFlags
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
	Dtls   string `json:"dtls,omitempty"`
	Length int    `json:"length,omitempty"`
}

// RegisterModule registers the zgrab2 module.
func init() {
	var module Module
	_, err := zgrab2.AddCommand("dtls", "Datagram Transport Layer Security", module.Description(), 443, &module)
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
	return "dtls"
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
	return "To check for dtls server"
}

// Help returns the module's help string.
func (f *Flags) Help() string {
	return ""
}

// Init initializes the Scanner with the command-line flags.
func (scanner *Scanner) Init(flags zgrab2.ScanFlags) error {
	f, _ := flags.(*Flags)
	scanner.config = f

	return nil
}

func (scanner *Scanner) Scan(target zgrab2.ScanTarget) (zgrab2.ScanStatus, interface{}, error) {
	var (
		conn    *dtls.Conn
		config  *dtls.Config
		results Results
		port    uint
		err     error
		logs    *logging.DefaultLoggerFactory
	)

	logs = logging.NewDefaultLoggerFactory()

	logs.DefaultLogLevel.Set(logging.LogLevelDebug)

	// If the port is supplied in ScanTarget, let that override the cmdline option
	if target.Port != nil {
		port = *target.Port
	} else {
		port = scanner.config.BaseFlags.Port
	}

	address := &net.UDPAddr{IP: net.ParseIP(target.Host()), Port: int(port)}

	certificate, err := selfsign.GenerateSelfSigned()
	if err != nil {
		// log.Fatalf("Error dialing: %v", err)
		return zgrab2.SCAN_UNKNOWN_ERROR, nil, err
	}
	// Prepare the configuration of the DTLS connection
	config = &dtls.Config{
		Certificates:         []tls.Certificate{certificate},
		InsecureSkipVerify:   true,
		ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
		LoggerFactory:        logs,
	}

	// Connect to a DTLS server
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err = dtls.DialWithContext(ctx, "udp", address, config)
	if err != nil {
		// log.Fatalf("Error dialing: %v", err)
		return zgrab2.SCAN_UNKNOWN_ERROR, nil, err
	}

	defer conn.Close()

	results.Dtls = ""
	//fmt.Printf("logs: %v\n", logs, results.Dtls)
	results.Length = len(results.Dtls)

	return zgrab2.SCAN_SUCCESS, &results, nil

}
