```sh
sudo apt install -y protobuf-compiler
```

```sh
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
```
```sh
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
```

```sh
sudo apt install -y libnetfilter-queue-dev
```

```sh
sudo systemctl stop opensnitch
sudo systemctl disable opensnitch
```

```sh
sudo codium --user-data-dir="~/.vscode-root"
```

```sh
Starting: /root/go/bin/dlv dap --log=true --log-output=debugger --listen=127.0.0.1:33037 --log-dest=3 from /home/<user>/workspace/opensnitch/daemon
DAP server listening at: 127.0.0.1:33037
```