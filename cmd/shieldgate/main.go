// ShieldGate — kernel-level firewall for Attack-Defense CTF.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"log"
	"net"
	"net/http"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"shieldgate/internal/api"
	"shieldgate/internal/board"
	ctfd "shieldgate/internal/board/ctfd"
	faust "shieldgate/internal/board/faust"
	forcad "shieldgate/internal/board/forcad"
	"shieldgate/internal/config"
	"shieldgate/internal/engine"
	"shieldgate/internal/engine/classifier"
	"shieldgate/internal/engine/mirror"
	"shieldgate/internal/engine/nfqueue"
	"shieldgate/internal/state"
	"shieldgate/internal/storage"
)

// runtime holds the pieces that can be re-created on settings change.
type runtime struct {
	mu     sync.Mutex
	cfg    *config.Config
	client board.BoardClient
	rules  *nfqueue.RuleManager
	queues []*nfqueue.Queue
}

func buildBoardClient(boardType, url, token, ourIP string, ports map[string]uint16) board.BoardClient {
	switch boardType {
	case "ctfd":
		return ctfd.New(url, token)
	case "faust":
		return faust.New(url)
	default:
		rest := forcad.New(url, token)
		if _, err := rest.GetServices(); err != nil {
			log.Printf("ForcAD REST API unreachable (%v); using scoreboard socket fallback", err)
			sock := forcad.NewSocket(url, ports)
			sock.SetOurIP(ourIP)
			return sock
		}
		return &forcad.PortOverride{Client: rest, Ports: ports}
	}
}

func main() {
	cfgPath := flag.String("config", "shieldgate.yaml", "path to config file")
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// --- Storage ---
	store, err := storage.Open(cfg.Storage.DBPath)
	if err != nil {
		log.Fatalf("storage: %v", err)
	}
	defer store.Close()

	rt := &runtime{cfg: cfg}

	// --- Board manager (client attached later via applySettings) ---
	mgr, err := state.NewManager(cfg, nil)
	if err != nil {
		log.Fatalf("state manager: %v", err)
	}

	hub := api.NewHub()
	broadcast := func(ev state.Event) {
		hub.Broadcast(api.Event{Type: ev.Type, ServiceID: ev.ServiceID, Message: ev.Message, At: ev.At})
	}
	mgr.OnEvent(broadcast)

	flows := classifier.NewManager(cfg.General.FlowTTL, cfg.General.MaxPayload)
	mir := mirror.New(cfg.Mirror.Enabled)

	var eng *engine.Engine
	var engineOnce sync.Once
	newEngine := func() *engine.Engine {
		engineOnce.Do(func() { eng = engine.New(nil, mgr, flows, mir, store) })
		return eng
	}
	_ = newEngine
	eng = engine.New(nil, mgr, flows, mir, store)
	eng.OnEvent(broadcast)
	go cleanupLoop(ctx, flows)

	// applySettings (re)connects the board, syncs services and reinstalls
	// the kernel interception for the current service list.
	applySettings := func(dto api.SettingsDTO) error {
		rt.mu.Lock()
		defer rt.mu.Unlock()

		cfg.Board.Type = dto.Board.Type
		cfg.Board.URL = dto.Board.URL
		cfg.Board.Token = dto.Board.Token
		cfg.Board.OurIP = dto.Board.OurIP
		cfg.Board.TaskPorts = dto.Board.TaskPorts
		cfg.Learn.RoundDuration = time.Duration(dto.RoundDurationMinutes) * time.Minute
		cfg.Learn.FlagRegex = dto.FlagRegex
		cfg.Optimize.BanFraction = dto.BanFraction

		if err := mgr.SetFlagPattern(dto.FlagRegex); err != nil {
			return err
		}
		mir.SetEnabled(dto.MirrorEnabled)

		client := buildBoardClient(dto.Board.Type, dto.Board.URL,
			dto.Board.Token, dto.Board.OurIP, dto.Board.TaskPorts)
		svcs, err := client.GetServices()
		if err != nil {
			return err
		}
		rt.client = client
		mgr.SetClient(client)
		mgr.SyncServices(svcs)
		log.Printf("board %s connected: %d services", dto.Board.Type, len(svcs))

		// Our team IP.
		var ourIP net.IP
		if dto.Board.OurIP != "" {
			ourIP = net.ParseIP(dto.Board.OurIP)
		} else if ip, err := client.GetOurIP(); err == nil {
			ourIP = ip
		}
		eng.SetOurIP(ourIP)
		if ourIP == nil {
			log.Printf("WARNING: our IP unknown")
		}

		// Mirror targets.
		if teams, err := client.GetTeams(); err == nil {
			targets := make([]net.IP, 0, len(teams))
			for _, t := range teams {
				if ourIP == nil || !t.IP.Equal(ourIP) {
					targets = append(targets, t.IP)
				}
			}
			mir.SetTargets(targets)
			log.Printf("mirror targets: %d teams", len(targets))
		}
		if cfg.Mirror.Enabled && !mir.Connected() {
			if err := mir.Connect(); err != nil {
				log.Printf("mirror raw socket unavailable (%v)", err)
			}
		}

		// Reinstall kernel interception.
		return rt.reinstallQueues(mgr, eng)
	}

	// Restore previously saved configuration, if any.
	if saved, ok := loadSavedSettings(store); ok {
		log.Printf("restoring saved configuration from database")
		if err := applySettings(saved); err != nil {
			log.Printf("WARNING: applying saved config failed: %v", err)
		}
	} else {
		log.Printf("no saved configuration; open the web UI to set up the board")
	}

	mgr.StartPolling(cfg.Board.PollInterval)

	// --- API server ---
	server := api.NewServer(api.ServerDeps{
		Manager:     mgr,
		Flows:       flows,
		Hub:         hub,
		Store:       store,
		Engine:      eng,
		Reconfigure: applySettings,
	})
	httpSrv := &http.Server{
		Addr:              cfg.API.Listen,
		Handler:           server,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		log.Printf("api listening on %s", cfg.API.Listen)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("http: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("shutting down...")
	shCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shCtx)
	mgr.Stop()
	rt.closeQueues()
	_ = mir.Close()
}

// reinstallQueues closes old queues/rules and installs fresh ones for the
// current TCP service list.
func (rt *runtime) reinstallQueues(mgr *state.Manager, h nfqueue.PacketHandler) error {
	rt.closeQueues()
	ports := make([]uint16, 0)
	for _, s := range mgr.All() {
		if s.Protocol == "tcp" && s.Port > 0 {
			ports = append(ports, s.Port)
		}
	}
	if len(ports) == 0 {
		log.Printf("no service ports configured yet — interception idle")
		return nil
	}
	rules := nfqueue.NewRuleManager(rt.cfg.NFQueue.StartNum)
	for i := range ports {
		qn := uint32(int(rt.cfg.NFQueue.StartNum) + i)
		q, err := nfqueue.Open(qn, rt.cfg.NFQueue.MaxQueueLen, rt.cfg.NFQueue.BatchSize, h)
		if err != nil {
			return err
		}
		rt.queues = append(rt.queues, q)
	}
	if err := rules.InstallPorts(ports); err != nil {
		return err
	}
	rt.rules = rules
	log.Printf("intercepting TCP ports %v via NFQUEUEs %d+", ports, rt.cfg.NFQueue.StartNum)
	return nil
}

func (rt *runtime) closeQueues() {
	for _, q := range rt.queues {
		q.Close()
	}
	rt.queues = nil
	if rt.rules != nil {
		if err := rt.rules.Teardown(); err != nil {
			log.Printf("nftables teardown: %v", err)
		}
		rt.rules = nil
	}
}

func loadSavedSettings(store *storage.DB) (api.SettingsDTO, bool) {
	raw, ok, err := store.GetSetting("app_config")
	if err != nil || !ok {
		return api.SettingsDTO{}, false
	}
	var dto api.SettingsDTO
	if err := json.Unmarshal([]byte(raw), &dto); err != nil || dto.Board.URL == "" {
		return api.SettingsDTO{}, false
	}
	return dto, true
}

func cleanupLoop(ctx context.Context, flows *classifier.Manager) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			flows.Cleanup()
		}
	}
}
