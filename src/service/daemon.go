package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	golog "log"
	"log/slog"
	"net"
	"os"
	"runtime"
	"runtime/pprof"
	"runtime/trace"
	"sync"
	"time"

	"github.com/evilsocket/opensnitch/daemon/conman"
	"github.com/evilsocket/opensnitch/daemon/core"
	"github.com/evilsocket/opensnitch/daemon/dns"
	"github.com/evilsocket/opensnitch/daemon/dns/systemd"
	"github.com/evilsocket/opensnitch/daemon/firewall"
	"github.com/evilsocket/opensnitch/daemon/log"
	"github.com/evilsocket/opensnitch/daemon/log/loggers"
	"github.com/evilsocket/opensnitch/daemon/netfilter"
	"github.com/evilsocket/opensnitch/daemon/netlink"
	"github.com/evilsocket/opensnitch/daemon/procmon/ebpf"
	"github.com/evilsocket/opensnitch/daemon/procmon/monitor"
	"github.com/evilsocket/opensnitch/daemon/rule"
	"github.com/evilsocket/opensnitch/daemon/statistics"
	"github.com/evilsocket/opensnitch/daemon/ui"
	"github.com/evilsocket/opensnitch/daemon/ui/protocol"

	"github.com/spf13/viper"
)

type closerFunc func() error

func overwriteLogging(cfg *viper.Viper) bool {
	var (
		debug     = cfg.GetBool("debug")
		warning   = cfg.GetBool("warning")
		important = cfg.GetBool("important")
		errorlog  = cfg.GetBool("error")
		logFile   = cfg.GetString("log-file")
		logMicro  = cfg.GetBool("log-micro")
	)

	return debug || warning || important || errorlog || logFile != "" || logMicro
}

func setupProfiling(config *viper.Viper) (traceCloserFn, memCloserFn, cpuCloserFn closerFunc, err error) {
	traceCloserFn = func() error { return nil }
	memCloserFn = func() error { return nil }
	cpuCloserFn = func() error { return nil }

	if traceFilename := config.GetString("trace-file"); traceFilename != "" {
		log.Info("setup trace profile %s", traceFilename)
		var fi *os.File
		fi, err := os.Create(traceFilename)
		if err != nil {
			err = fmt.Errorf("could not create trace profile: %w", err)
			return traceCloserFn, memCloserFn, cpuCloserFn, err
		}
		trace.Start(fi)

		traceCloserFn = func() error {
			trace.Stop()
			return fi.Close()
		}
	}

	if memProfile := config.GetString("mem-profile"); memProfile != "" {
		log.Info("setup mem profile %s", memProfile)
		var fi *os.File
		fi, err = os.Create(memProfile)
		if err != nil {
			err = fmt.Errorf("could not create memory profile: %w", err)
			return traceCloserFn, memCloserFn, cpuCloserFn, err
		}

		memCloserFn = func() error {
			runtime.GC() // get up-to-date statistics

			if err := pprof.WriteHeapProfile(fi); err != nil {
				log.Error("could not write memory profile %w", err)
			}
			log.Info("writing mem profile %s", memProfile)

			return fi.Close()
		}
	}

	if cpuProfile := config.GetString("cpu-profile"); cpuProfile != "" {
		log.Info("setup cpu profile: %s", cpuProfile)
		var fi *os.File
		fi, err = os.Create(cpuProfile)
		if err != nil {
			err = fmt.Errorf("could not create cpu profile: %w", err)
			return traceCloserFn, memCloserFn, cpuCloserFn, err
		}

		if err = pprof.StartCPUProfile(fi); err != nil {
			err = fmt.Errorf("could not start cpu profile: %w", err)
			return traceCloserFn, memCloserFn, cpuCloserFn, err
		}

		cpuCloserFn = func() error {
			pprof.StopCPUProfile()
			return fi.Close()
		}
	}

	return traceCloserFn, memCloserFn, cpuCloserFn, err
}

func setupLogging(config *viper.Viper) {
	golog.SetOutput(io.Discard)
	if config.GetBool("debug") {
		log.SetLogLevel(log.DEBUG)
	} else if config.GetBool("warning") {
		log.SetLogLevel(log.WARNING)
	} else if config.GetBool("important") {
		log.SetLogLevel(log.IMPORTANT)
	} else if config.GetBool("error") {
		log.SetLogLevel(log.ERROR)
	} else {
		log.SetLogLevel(log.INFO)
	}

	log.SetLogUTC(config.GetBool("logUTC"))
	log.SetLogMicro(config.GetBool("logMicro"))

	var logFileToUse string
	if logFile := config.GetString("logFile, "); logFile == "" {
		logFileToUse = log.StdoutFile
	} else {
		logFileToUse = logFile
	}

	log.Close()
	if err := log.OpenFile(logFileToUse); err != nil {
		log.Error("Error opening user defined log: %s %s", logFileToUse, err)
	}
}

// Listen to events sent from other modules
func listenToEvents(uiClient *ui.Client) {
	var num = 5
	slog.Debug("starting ui listeners", "listeners", num)
	for i := 0; i < num; i++ { // TODO: why 5?
		go func(uiClient *ui.Client) {
			for evt := range ebpf.Events() {
				// for loop vars are per-loop, not per-item
				evt := evt
				uiClient.PostAlert(
					protocol.Alert_WARNING,
					protocol.Alert_KERNEL_EVENT,
					protocol.Alert_SHOW_ALERT,
					protocol.Alert_MEDIUM,
					evt)
			}
		}(uiClient)
	}
}

func initSystemdResolvedMonitor() {
	resolvMonitor, err := systemd.NewResolvedMonitor()
	if err != nil {
		log.Debug("[DNS] Unable to use systemd-resolved monitor: %s", err)
		return
	}
	_, err = resolvMonitor.Connect()
	if err != nil {
		log.Debug("[DNS] Connecting to systemd-resolved: %s", err)
		return
	}
	err = resolvMonitor.Subscribe()
	if err != nil {
		log.Debug("[DNS] Subscribing to systemd-resolved DNS events: %s", err)
		return
	}
	go func() {
		var ip net.IP
		for {
			select {
			case exit := <-resolvMonitor.Exit():
				if exit == nil {
					log.Info("[DNS] systemd-resolved monitor stopped")
					return
				}
				log.Debug("[DNS] systemd-resolved monitor disconnected. Reconnecting...")
			case response := <-resolvMonitor.GetDNSResponses():
				if response.State != systemd.SuccessState {
					log.Debug("[DNS] systemd-resolved monitor response error: %v", response)
					continue
				}
				/*for i, q := range response.Question {
					log.Debug("%d SYSTEMD RESPONSE Q: %s", i, q.Name)
				}*/
				for i, a := range response.Answer {
					if a.RR.Key.Type != systemd.DNSTypeA &&
						a.RR.Key.Type != systemd.DNSTypeAAAA &&
						a.RR.Key.Type != systemd.DNSTypeCNAME {
						log.Debug("systemd-resolved, excluding answer: %#v", a)
						continue
					}
					ip = net.IP(a.RR.Address)
					log.Debug("%d systemd-resolved monitor response: %s -> %s", i, a.RR.Key.Name, ip)
					if a.RR.Key.Type == systemd.DNSTypeCNAME {
						log.Debug("systemd-resolved CNAME >> %s -> %s", a.RR.Name, a.RR.Key.Name)
						dns.Track(a.RR.Name, a.RR.Key.Name /*domain*/)
					} else {
						dns.Track(ip.String(), a.RR.Key.Name /*domain*/)
					}
				}
			}
		}
	}()
}

type Service struct {
	numWorkers               int
	queueNum, repeatQueueNum int
	queue, repeatQueue       *netfilter.Queue
	uiClient                 *ui.Client
	stats                    *statistics.Statistics
	resolveMonitor           *systemd.ResolvedMonitor
	rules                    *rule.Loader
	repeatPktChan            <-chan netfilter.Packet
	cfg                      *viper.Viper
	cpuProfileCloserFn       func() error
	memProfileCloserFn       func() error
	traceProfileCloserFn     func() error
	mu                       *sync.Mutex
}

func New(cfg *viper.Viper) (*Service, error) {
	slog.Debug("configuring service logging")
	if overwriteLogging(cfg) {
		setupLogging(cfg)
	}

	slog.Debug("configuring service profiling")
	traceCloserFn, memCloserFn, cpuCloserFn, err := setupProfiling(cfg)
	if err != nil {
		return nil, err
	}

	slog.Debug("configuring service rules")
	rulesPath := cfg.GetString("rules.path")
	if rulesPath == "" {
		return nil, fmt.Errorf("rules path cannot be empty")
	}

	log.Info("Loading rules from %s ...", rulesPath)
	rules, err := rule.NewLoader(!cfg.GetBool("no-live-reload"))
	if err != nil {
		return nil, err
	}

	if err = rules.Load(rulesPath); err != nil {
		return nil, err
	}

	slog.Debug("configuring service UI client", "ui-socket", cfg.GetString("ui-socket"), "config-file", cfg.GetString("config-file"))
	stats := statistics.New(rules)
	loggerMgr := loggers.NewLoggerManager()

	uiClient := ui.NewClient(cfg.GetString("ui-socket"), cfg.GetString("config-file"), stats, rules, loggerMgr)
	uiClient.Connect()

	slog.Debug("listening to UI events")
	listenToEvents(uiClient) // listen to UI events

	// overwrite monitor method from configuration if the user has passed
	// the option via command line.
	slog.Debug("configuring service process monitor")
	if procmonMethod := cfg.GetString("process-monitor-method"); procmonMethod != "" {
		ebpfModPath := cfg.GetString("ebpf.modulespath")
		if err := monitor.ReconfigureMonitorMethod(procmonMethod, ebpfModPath); err != nil {
			msg := fmt.Sprintf("Unable to set process monitor method via parameter: %v", err)
			uiClient.SendWarningAlert(msg)
			log.Warning(msg)
		}
	}

	slog.Debug("configuring service systemd resolver")
	initSystemdResolvedMonitor()

	return &Service{
		numWorkers:           cfg.GetInt("workers"),
		uiClient:             uiClient,
		stats:                stats,
		rules:                rules,
		cfg:                  cfg,
		cpuProfileCloserFn:   cpuCloserFn,
		memProfileCloserFn:   memCloserFn,
		traceProfileCloserFn: traceCloserFn,
		mu:                   new(sync.Mutex),
	}, err
}

func (svc *Service) Run(ctx context.Context) error {
	log.Important("Starting %s v%s", core.Name, core.Version)
	svc.mu.Lock()
	defer svc.mu.Unlock()

	slog.Debug("starting worker routines", "workers", svc.cfg.GetString("workers"), "queue-num", svc.cfg.GetInt("queue-num"))
	// setup the workers
	wrkChan := make(chan netfilter.Packet)
	for i := 0; i < svc.numWorkers; i++ {
		go svc.worker(ctx, i, wrkChan)
	}
	defer func() {
		close(wrkChan)
	}()

	var queueNum int = svc.cfg.GetInt("queue-num")
	repeatQueueNum := queueNum + 1

	slog.Debug("starting netfilter queue listeners", "queue-num", queueNum, "repeat-queue-num", repeatQueueNum)
	// prepare the queue
	queue, err := netfilter.NewQueue(uint16(queueNum))
	if err != nil {
		msg := fmt.Sprintf("Error creating queue #%d: %s", queueNum, err)
		svc.uiClient.SendWarningAlert(msg)
		log.Warning("Is opensnitchd already running?")
		log.Fatal(msg)
	}
	pktChan := queue.Packets()

	slog.Debug("starting netfilter repeat queue listener", "queue-num", queueNum, "repeat-queue-num", repeatQueueNum)
	repeatQueue, err := netfilter.NewQueue(uint16(repeatQueueNum))
	if err != nil {
		msg := fmt.Sprintf("Error creating repeat queue #%d: %s", repeatQueueNum, err)
		svc.uiClient.SendErrorAlert(msg)
		log.Warning("Is opensnitchd already running?")
		log.Warning(msg)
	}
	repeatPktChan := repeatQueue.Packets()

	fwConfigFile := svc.cfg.GetString("fw-config-file")
	monitorDuration := svc.cfg.GetDuration("fw-monitor-duration")
	slog.Debug("initializing firewall", "fw-config-file", fwConfigFile, "fw-monitor-duration", monitorDuration.String(), "queue-num", queueNum)
	// queue is ready, run firewall rules and start intercepting connections
	if err = firewall.Init(svc.uiClient.GetFirewallType(), fwConfigFile, monitorDuration.String(), &queueNum); err != nil {
		log.Warning("%s", err)
		svc.uiClient.SendWarningAlert(err)
	}

	go func(uiClient *ui.Client, ebpfPath string) {
		// this will close via interupt signals
		slog.Debug("loading service ebpf dns listener", "ebpfPath", ebpfPath)
		err := dns.ListenerEbpf(ebpfPath) // runs in background
		if err == nil {
			slog.Debug("ebpf dns listener closed", "ebpfPath", ebpfPath)
			return // successfully closed epbf dns module
		}

		msg := fmt.Sprintf("EBPF-DNS: Unable to attach ebpf listener: %s", err)
		log.Warning(msg)
		// don't display an alert, since this module is not critical
		uiClient.PostAlert(
			protocol.Alert_ERROR,
			protocol.Alert_GENERIC,
			protocol.Alert_SAVE_TO_DB,
			protocol.Alert_MEDIUM,
			msg)
	}(svc.uiClient, svc.cfg.GetString("ebpf.modulespath"))

	slog.Debug("setting service variables")
	// TODO: remove variable setting
	svc.queueNum = queueNum
	svc.repeatQueueNum = repeatQueueNum
	svc.queue = queue
	svc.repeatQueue = repeatQueue
	svc.repeatPktChan = repeatPktChan

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()

		slog.Debug("running on netfilter queue", "queue-num", queueNum)
		for {
			select {
			case <-ctx.Done():
				slog.Debug("service received context done", "error", ctx.Err().Error())
				return
			case pkt, chanOpen := <-pktChan:
				if !chanOpen {
					return
				}
				wrkChan <- pkt
			}
		}
	}()

	slog.Debug("service running")
	wg.Wait()
	return nil
}

func (svc *Service) Stop(ctx context.Context) error {
	var err error

	log.Info("Cleaning up ...")
	firewall.Stop()
	monitor.End()
	svc.uiClient.Close()

	if svc.resolveMonitor != nil {
		svc.resolveMonitor.Close()
	}

	if closeErr := svc.cpuProfileCloserFn(); closeErr != nil {
		err = errors.Join(err, closeErr)
	}

	if closeErr := svc.memProfileCloserFn(); closeErr != nil {
		err = errors.Join(err, closeErr)
	}

	if closeErr := svc.traceProfileCloserFn(); closeErr != nil {
		err = errors.Join(err, closeErr)
	}

	svc.repeatQueue.Close()
	svc.queue.Close()

	return err
}

func (svc *Service) worker(ctx context.Context, id int, wrkChan <-chan netfilter.Packet) {
	defer func() {
		log.Debug("worker #%d exit", id)
	}()

	log.Debug("Worker #%d started.", id)
	for {
		select {
		case <-ctx.Done():
			slog.Debug("worker context done", "error", ctx.Err().Error(), "id", id)
			return
		case pkt, chanOpen := <-wrkChan:
			if !chanOpen {
				slog.Debug("worker channel closed", "id", id)
				return
			}
			slog.Debug("worker received packet", "uid", pkt.UID, "id", id)
			svc.onPacket(pkt)
		}
	}
}

func (svc *Service) onPacket(packet netfilter.Packet) {
	// DNS response, just parse, track and accept.
	if dns.TrackAnswers(packet.Packet) == true {
		packet.SetVerdictAndMark(netfilter.NF_ACCEPT, packet.Mark)
		svc.stats.OnDNSResponse()
		return
	}

	// Parse the connection state
	con := conman.Parse(packet, svc.uiClient.InterceptUnknown())
	if con == nil {
		svc.applyDefaultAction(&packet)
		return
	}
	// accept our own connections
	if con.Process.ID == os.Getpid() {
		packet.SetVerdict(netfilter.NF_ACCEPT)
		return
	}

	// search a match in preloaded rules
	r := svc.acceptOrDeny(&packet, con)

	if r != nil && r.Nolog {
		return
	}
	// XXX: if a connection is not intercepted due to InterceptUnknown == false,
	// it's not sent to the server, which leads to miss information.
	svc.stats.OnConnectionEvent(con, r, r == nil)
}

func (svc *Service) applyDefaultAction(packet *netfilter.Packet) {
	if svc.uiClient.DefaultAction() == rule.Allow {
		packet.SetVerdictAndMark(netfilter.NF_ACCEPT, packet.Mark)
	} else {
		packet.SetVerdict(netfilter.NF_DROP)
	}
}

func (svc *Service) acceptOrDeny(packet *netfilter.Packet, con *conman.Connection) *rule.Rule {
	r := svc.rules.FindFirstMatch(con)
	if r == nil {
		// no rule matched
		// Note that as soon as we set a verdict on a packet, the next packet in the netfilter queue
		// will begin to be processed even if this function hasn't yet returned

		// send a request to the UI client if
		// 1) connected and running and 2) we are not already asking
		if svc.uiClient.Connected() == false || svc.uiClient.GetIsAsking() == true {
			svc.applyDefaultAction(packet)
			log.Debug("UI is not running or busy, connected: %v, running: %v", svc.uiClient.Connected(), svc.uiClient.GetIsAsking())
			return nil
		}

		svc.uiClient.SetIsAsking(true)
		defer svc.uiClient.SetIsAsking(false)

		// In order not to block packet processing, we send our packet to a different netfilter queue
		// and then immediately pull it back out of that queue
		packet.SetRequeueVerdict(uint16(svc.repeatQueueNum))

		var o bool
		var pkt netfilter.Packet
		// don't wait for the packet longer than 1 sec
		select {
		case pkt, o = <-svc.repeatPktChan:
			if !o {
				log.Debug("error while receiving packet from repeatPktChan")
				return nil
			}
		case <-time.After(1 * time.Second):
			log.Debug("timed out while receiving packet from repeatPktChan")
			return nil
		}

		//check if the pulled out packet is the same we put in
		if res := bytes.Compare(packet.Packet.Data(), pkt.Packet.Data()); res != 0 {
			log.Error("The packet which was requeued has changed abruptly. This should never happen. Please report this incident to the Opensnitch developers. %v %v ", packet, pkt)
			return nil
		}
		packet = &pkt

		// Update the hostname again.
		// This is required due to a race between the ebpf dns hook and the actual first packet beeing sent
		if con.DstHost == "" {
			con.DstHost = dns.HostOr(con.DstIP, con.DstHost)
		}

		r = svc.uiClient.Ask(con)
		if r == nil {
			log.Error("Invalid rule received, applying default action")
			svc.applyDefaultAction(packet)
			return nil
		}
		ok := false
		pers := ""
		action := string(r.Action)
		if r.Action == rule.Allow {
			action = log.Green(action)
		} else {
			action = log.Red(action)
		}

		// check if and how the rule needs to be saved
		if r.Duration == rule.Always {
			pers = "Saved"
			// add to the loaded rules and persist on disk
			if err := svc.rules.Add(r, true); err != nil {
				log.Error("Error while saving rule: %s", err)
			} else {
				ok = true
			}
		} else {
			pers = "Added"
			// add to the rules but do not save to disk
			if err := svc.rules.Add(r, false); err != nil {
				log.Error("Error while adding rule: %s", err)
			} else {
				ok = true
			}
		}

		if ok {
			log.Important("%s new rule: %s if %s", pers, action, r.Operator.String())
		}
	}

	if packet == nil {
		log.Debug("Packet nil after processing rules")
		return r
	}

	if r.Enabled == false {
		svc.applyDefaultAction(packet)
		ruleName := log.Green(r.Name)
		log.Info("DISABLED (%s) %s %s -> %s:%d (%s)", svc.uiClient.DefaultAction(), log.Bold(log.Green("✔")), log.Bold(con.Process.Path), log.Bold(con.To()), con.DstPort, ruleName)

	} else if r.Action == rule.Allow {
		packet.SetVerdictAndMark(netfilter.NF_ACCEPT, packet.Mark)
		ruleName := log.Green(r.Name)
		if r.Operator.Operand == rule.OpTrue {
			ruleName = log.Dim(r.Name)
		}
		log.Debug("%s %s -> %d:%s => %s:%d, mark: %x (%s)", log.Bold(log.Green("✔")), log.Bold(con.Process.Path), con.SrcPort, log.Bold(con.SrcIP.String()), log.Bold(con.To()), con.DstPort, packet.Mark, ruleName)
	} else {
		if r.Action == rule.Reject {
			netlink.KillSocket(con.Protocol, con.SrcIP, con.SrcPort, con.DstIP, con.DstPort)
		}
		packet.SetVerdict(netfilter.NF_DROP)

		log.Debug("%s %s -> %d:%s => %s:%d, mark: %x (%s)", log.Bold(log.Red("✘")), log.Bold(con.Process.Path), con.SrcPort, log.Bold(con.SrcIP.String()), log.Bold(con.To()), con.DstPort, packet.Mark, log.Red(r.Name))
	}

	return r
}
