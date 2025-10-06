package wireguard

type Configuration struct {
	Server  ServerConfiguration
	Clients map[string]ClientConfiguration
}

type ServerConfiguration struct {
	PublicIP   string
	Address    string
	ListenPort uint16
	KeySet     KeySet
	Interface  string
	DNS        []string
}

type ClientConfiguration struct {
	Address    string
	KeySet     KeySet
	AllowedIPs []string
}
