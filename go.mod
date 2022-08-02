module github.com/zmap/zgrab2

go 1.12

require (
	github.com/RumbleDiscovery/jarm-go v0.0.6
	github.com/pion/dtls/v2 v2.1.5
	github.com/pion/logging v0.2.2
	github.com/prometheus/client_golang v1.12.2
	github.com/prometheus/common v0.35.0 // indirect
	github.com/sirupsen/logrus v1.8.1
	// github.com/zmap/rc2 v0.0.0-20190804163417-abaa70531248 // indirect
	github.com/zmap/zcrypto v0.0.0-20220222153637-55904056ad9f
	github.com/zmap/zflags v1.4.0-beta.1.0.20200204220219-9d95409821b6
	golang.org/x/crypto v0.0.0-20220622213112-05595931fe9d
	golang.org/x/net v0.0.0-20220708220712-1185a9018129
	golang.org/x/sys v0.0.0-20220708085239-5a0f0661e09d
	golang.org/x/text v0.3.7
	google.golang.org/protobuf v1.28.0 // indirect
	gopkg.in/check.v1 v1.0.0-20190902080502-41f04d3bba15
	gopkg.in/mgo.v2 v2.0.0-20190816093944-a6b53ec6cb22
	gopkg.in/yaml.v2 v2.4.0
)

// TODO: remove when done
// replace github.com/zmap/zcrypto => /home/dissoupov/code/censys/zcrypto
