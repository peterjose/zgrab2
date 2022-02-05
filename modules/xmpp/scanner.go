package xmpp

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"regexp"
	"strconv"

	log "github.com/sirupsen/logrus"

	"github.com/zmap/zgrab2"
)

type Flags struct {
	zgrab2.BaseFlags
	zgrab2.TLSFlags
	Stanza     string `long:"stanza" default:"<stream:stream xmlns='jabber:client'\\nxmlns:stream='http://etherx.jabber.org/streams'\\nxmlns:tls='http://www.ietf.org/rfc/rfc2595.txt'\\nto='jabber.org'>" description:"Stanza to send to the server. Mutually exclusive with --stanza-file" `
	StanzaFile string `long:"stanza-file" description:"Read xml stanza from file as byte array (hex). Mutually exclusive with --stanza"`
	Pattern    string `long:"pattern" default:"stream:stream" description:"Pattern to match, must be valid regexp."`
	UseTLS     bool   `long:"tls" description:"Sends xml stanza with TLS connection. Loads TLS module command options. "`
	MaxTries   int    `long:"max-tries" default:"1" description:"Number of tries for timeouts and connection errors before giving up. Includes making TLS connection if enabled."`
}

type Module struct {
}

type Scanner struct {
	config *Flags
	regex  *regexp.Regexp
	stanza []byte
}

func init() {
	var tlsModule Module
	_, err := zgrab2.AddCommand("xmpp", "Extensible Messaging & Presence Protocol", tlsModule.Description(), 5222, &tlsModule)
	if err != nil {
		log.Fatal(err)
	}
}

// ScanResults instances are returned by the module's Scan function.
type Results struct {
	Xmpp   string         `json:"xmpp,omitempty"`
	Length int            `json:"length,omitempty"`
	TLSLog *zgrab2.TLSLog `json:"tls,omitempty"`
}

// RegisterModule is called by modules/xmpp.go to register the scanner.
func RegisterModule() {
	var module Module
	_, err := zgrab2.AddCommand("xmpp", "XMPP", module.Description(), 5222, &module)
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
	if f.Stanza != "<stream:stream xmlns='jabber:client'\\nxmlns:stream='http://etherx.jabber.org/streams'\\nxmlns:tls='http://www.ietf.org/rfc/rfc2595.txt'\\nto='jabber.org'>" && f.StanzaFile != "" {
		log.Fatal("Cannot set both --stanza and --stanza-file")
		return zgrab2.ErrInvalidArguments
	}
	return nil
}

// Description returns an overview of this module.
func (module *Module) Description() string {
	return "Extensible Messaging & Presence Protocol"
}

// Help returns the module's help string.
func (f *Flags) Help() string {
	return ""
}

// Init initializes the Scanner with the command-line flags.
func (scanner *Scanner) Init(flags zgrab2.ScanFlags) error {
	var err error
	f, _ := flags.(*Flags)
	scanner.config = f
	scanner.regex = regexp.MustCompile(scanner.config.Pattern)
	if len(f.StanzaFile) != 0 {
		scanner.stanza, err = ioutil.ReadFile(f.StanzaFile)
		if err != nil {
			log.Fatal("Failed to open stanza file")
			return zgrab2.ErrInvalidArguments
		}
	} else {
		strProbe, err := strconv.Unquote(fmt.Sprintf(`"%s"`, scanner.config.Stanza))
		if err != nil {
			panic("Stanza error")
		}
		scanner.stanza = []byte(strProbe)
	}

	return nil
}

var NoMatchError = errors.New("pattern did not match")

func (scanner *Scanner) Scan(target zgrab2.ScanTarget) (zgrab2.ScanStatus, interface{}, error) {
	try := 0
	var (
		conn    net.Conn
		tlsConn *zgrab2.TLSConnection
		results Results
		err     error
		readerr error
	)
	for try < scanner.config.MaxTries {
		try++
		conn, err = target.Open(&scanner.config.BaseFlags)
		if err != nil {
			continue
		}
		if scanner.config.UseTLS {
			tlsConn, err = scanner.config.TLSFlags.GetTLSConnection(conn)
			if err != nil {
				continue
			}
			if err = tlsConn.Handshake(); err != nil {
				continue
			}
			results.TLSLog = tlsConn.GetLog()
			conn = tlsConn
		}

		break
	}
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	defer conn.Close()

	var ret []byte
	try = 0
	for try < scanner.config.MaxTries {
		try++
		_, err = conn.Write(scanner.stanza)
		ret, readerr = zgrab2.ReadAvailable(conn)
		if err != nil {
			continue
		}
		if readerr != io.EOF && readerr != nil {
			continue
		}
		break
	}
	if err != nil {
		return zgrab2.TryGetScanStatus(err), &results, err
	}
	if readerr != io.EOF && readerr != nil {
		return zgrab2.TryGetScanStatus(readerr), &results, readerr
	}
	results.Xmpp = string(ret)
	results.Length = len(ret)

	if scanner.regex.Match(ret) {
		return zgrab2.SCAN_SUCCESS, &results, nil
	}

	return zgrab2.SCAN_PROTOCOL_ERROR, &results, NoMatchError

}

// Protocol returns the protocol identifer for the scanner.
func (s *Scanner) Protocol() string {
	return "xmpp"
}
