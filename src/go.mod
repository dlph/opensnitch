module github.com/dlph/opensnitch

go 1.21.1

replace github.com/evilsocket/opensnitch/daemon/ui/protocol => ../daemon/ui/protocol

require (
	github.com/evilsocket/opensnitch/daemon v0.0.0-20240211104149-2ec37ed5939c
	github.com/evilsocket/opensnitch/daemon/ui/protocol v0.0.0-00010101000000-000000000000
	github.com/fsnotify/fsnotify v1.7.0
	github.com/iovisor/gobpf v0.2.0
	github.com/matryer/is v1.4.1
	github.com/spf13/afero v1.11.0
	github.com/spf13/cobra v1.8.0
	github.com/spf13/viper v1.18.2
	go.starlark.net v0.0.0-20240411212711-9b43f0afd521
	go.uber.org/zap v1.27.0
	golang.org/x/sync v0.7.0
)

require (
	github.com/BurntSushi/toml v0.4.1 // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/google/go-cmp v0.6.0 // indirect
	github.com/google/gopacket v1.1.19 // indirect
	github.com/google/nftables v0.1.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/josharian/native v0.0.0-20200817173448-b6b71def0850 // indirect
	github.com/magiconair/properties v1.8.7 // indirect
	github.com/mdlayher/netlink v1.4.2 // indirect
	github.com/mdlayher/socket v0.0.0-20211102153432-57e3fa563ecb // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/pelletier/go-toml/v2 v2.1.0 // indirect
	github.com/sagikazarmark/locafero v0.4.0 // indirect
	github.com/sagikazarmark/slog-shim v0.1.0 // indirect
	github.com/sourcegraph/conc v0.3.0 // indirect
	github.com/spf13/cast v1.6.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/subosito/gotenv v1.6.0 // indirect
	github.com/varlink/go v0.4.0 // indirect
	github.com/vishvananda/netlink v1.1.1-0.20220115184804-dd687eb2f2d4 // indirect
	github.com/vishvananda/netns v0.0.0-20200728191858-db3c7e526aae // indirect
	go.uber.org/multierr v1.10.0 // indirect
	golang.org/x/exp v0.0.0-20230905200255-921286631fa9 // indirect
	golang.org/x/mod v0.12.0 // indirect
	golang.org/x/net v0.21.0 // indirect
	golang.org/x/sys v0.17.0 // indirect
	golang.org/x/text v0.14.0 // indirect
	golang.org/x/tools v0.13.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240227224415-6ceb2ff114de // indirect
	google.golang.org/grpc v1.63.2 // indirect
	google.golang.org/protobuf v1.33.0 // indirect
	gopkg.in/ini.v1 v1.67.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	honnef.co/go/tools v0.2.2 // indirect
)
