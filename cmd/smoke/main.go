// Smoke test: config → board client → manager sync + poll. No root needed.
package main

import (
	"flag"
	"log"

	"shieldgate/internal/board"
	forcad "shieldgate/internal/board/forcad"
	"shieldgate/internal/config"
	"shieldgate/internal/state"
)

func main() {
	cfgPath := flag.String("config", "shieldgate.yaml", "config")
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatal(err)
	}

	client := buildClient(cfg)

	svcs, err := client.GetServices()
	if err != nil {
		log.Fatalf("GetServices: %v", err)
	}
	log.Printf("services (%d):", len(svcs))
	for _, s := range svcs {
		log.Printf("  %-20s port=%d proto=%s id=%s", s.Name, s.Port, s.Protocol, s.ID)
	}

	mgr, err := state.NewManager(cfg, client)
	if err != nil {
		log.Fatal(err)
	}
	mgr.SyncServices(svcs)

	statuses, err := client.Poll()
	if err != nil {
		log.Fatalf("Poll: %v", err)
	}
	for id, st := range statuses {
		svc, _ := mgr.Get(id)
		name := ""
		if svc != nil {
			name = svc.Name
		}
		log.Printf("checker %-25s (%s) = %s", id, name, st)
	}

	teams, _ := client.GetTeams()
	log.Printf("mirror targets available: %d teams", len(teams))
	ip, err := client.GetOurIP()
	log.Printf("our IP: %s (err=%v)", ip, err)
}

func buildClient(cfg *config.Config) board.BoardClient {
	rest := forcad.New(cfg.Board.URL, cfg.Board.Token)
	if _, err := rest.GetServices(); err != nil {
		log.Printf("REST API unreachable (%v); using scoreboard socket fallback", err)
		sock := forcad.NewSocket(cfg.Board.URL, cfg.Board.TaskPorts)
		sock.SetOurIP(cfg.Board.OurIP)
		return sock
	}
	return &forcad.PortOverride{Client: rest, Ports: cfg.Board.TaskPorts}
}
