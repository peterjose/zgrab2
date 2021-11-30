package upnp

import (
	log "github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2"
)

type Flags struct {
	zgrab2.BaseFlags
}

type Module struct {
}

type Scanner struct {
	config *Flags
}

func init() {
	var Module Module
	_, err := zgrab2.AddCommand("upnp", "UPnP", Module.Description(), 1900, &Module)
	if err != nil {
		log.Fatal(err)
	}
}

func (m *Module) NewFlags() interface{} {
	return new(Flags)
}

func (m *Module) NewScanner() zgrab2.Scanner {
	return new(Scanner)
}

// Description returns an overview of this module.
func (m *Module) Description() string {
	return "Perform a UPnP connection"
}

func (f *Flags) Validate(args []string) error {
	return nil
}

func (f *Flags) Help() string {
	return ""
}

func (s *Scanner) Init(flags zgrab2.ScanFlags) error {
	f, ok := flags.(*Flags)
	if !ok {
		return zgrab2.ErrMismatchedFlags
	}
	s.config = f
	return nil
}

func (s *Scanner) GetName() string {
	return s.config.Name
}

func (s *Scanner) GetTrigger() string {
	return s.config.Trigger
}

func (s *Scanner) InitPerSender(senderID int) error {
	return nil
}

func (s *Scanner) Scan(t zgrab2.ScanTarget) (zgrab2.ScanStatus, interface{}, error) {
	return zgrab2.SCAN_SUCCESS, nil, nil
}

// Protocol returns the protocol identifer for the scanner.
func (s *Scanner) Protocol() string {
	return "upnp"
}
