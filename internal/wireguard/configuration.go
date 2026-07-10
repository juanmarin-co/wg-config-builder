package wireguard

type Configuration struct {
	Hosts map[string]HostConfiguration `yaml:"hosts"`
}

type HostConfiguration struct {
	Interface HostInterfaceConfiguration       `yaml:"interface"`
	Peers     map[string]HostPeerConfiguration `yaml:"peers"`
}

type HostInterfaceConfiguration struct {
	Address    string   `yaml:"address"`
	MTU        uint16   `yaml:"mtu"`
	ListenPort uint16   `yaml:"listenPort"`
	DNS        []string `yaml:"dns"`
	PrivateKey string   `yaml:"privateKey"`
	PostUp     []string `yaml:"postUp"`
	PostDown   []string `yaml:"postDown"`
}

type HostPeerConfiguration struct {
	PublicKey           string   `yaml:"publicKey"`
	PreSharedKey        string   `yaml:"presharedKey"`
	Endpoint            string   `yaml:"endpoint"`
	AllowedIPs          []string `yaml:"allowedIps"`
	PersistentKeepalive uint16   `yaml:"persistentKeepalive"`
}
