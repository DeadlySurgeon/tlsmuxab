package services

import (
	"crypto/tls"
)

type Service string

// Various Services
const (
	Alpha   Service = "alpha"
	Beta    Service = "beta"
	Gamma   Service = "gamma"
	Delta   Service = "delta"
	Epsilon Service = "epsilon"
)

var portMap = map[Service]int{
	Alpha:   9901,
	Beta:    9902,
	Gamma:   9903,
	Delta:   9904,
	Epsilon: 9905,
}

func (s Service) Port() int { return portMap[s] }

func (s Service) Cert() (tls.Certificate, error) {
	sn := string(s)
	return tls.LoadX509KeyPair(
		"certs/servers/"+sn+"-cert.pem",
		"certs/servers/"+sn+"-key.pem",
	)
}
