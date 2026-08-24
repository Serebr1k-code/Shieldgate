// Package config loads and validates ShieldGate configuration.
package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/viper"
)

type Config struct {
	General  General  `mapstructure:"general"`
	NFQueue  NFQueue  `mapstructure:"nfqueue"`
	Learn    Learn    `mapstructure:"learn"`
	Optimize Optimize `mapstructure:"optimize"`
	Mirror   Mirror   `mapstructure:"mirror"`
	Storage  Storage  `mapstructure:"storage"`
	API      API      `mapstructure:"api"`
	Board    Board    `mapstructure:"board"`
}

type General struct {
	Interface  string        `mapstructure:"interface"`
	FlowTTL    time.Duration `mapstructure:"flow_ttl"`
	MaxPayload int           `mapstructure:"max_payload_bytes"`
}

type NFQueue struct {
	StartNum    uint16 `mapstructure:"start_num"`
	BatchSize   uint32 `mapstructure:"batch_size"`
	MaxQueueLen uint32 `mapstructure:"max_queue_len"`
}

type Learn struct {
	RoundDuration time.Duration `mapstructure:"round_duration"`
	FlagRegex     string        `mapstructure:"flag_regex"`
}

type Optimize struct {
	BanFraction float64       `mapstructure:"ban_fraction"`
	CycleWait   time.Duration `mapstructure:"cycle_wait"` // n*2 normally; overridable for tests
}

type Mirror struct {
	Enabled bool `mapstructure:"enabled"`
}

type Storage struct {
	DBPath      string `mapstructure:"db_path"`
	PcapDir     string `mapstructure:"pcap_dir"`
	PcapEnabled bool   `mapstructure:"pcap_enabled"`
}

type API struct {
	Listen string `mapstructure:"listen"`
}

type Board struct {
	Type         string        `mapstructure:"type"` // forcad | ctfd | faust
	URL          string        `mapstructure:"url"`
	Token        string        `mapstructure:"token"`
	PollInterval time.Duration `mapstructure:"poll_interval"`
	OurIP        string        `mapstructure:"our_ip"`
	// TaskPorts maps service names to TCP ports; needed when the board does
	// not expose ports (e.g. ForcAD public scoreboard via socket.io).
	TaskPorts map[string]uint16 `mapstructure:"task_ports"`
}

func Defaults() *Config {
	return &Config{
		General:  General{Interface: "eth0", FlowTTL: 5 * time.Minute, MaxPayload: 64 * 1024},
		NFQueue:  NFQueue{StartNum: 100, BatchSize: 128, MaxQueueLen: 4096},
		Learn:    Learn{RoundDuration: 2 * time.Minute, FlagRegex: `[A-Za-z0-9]{31}=`},
		Optimize: Optimize{BanFraction: 0.25},
		Mirror:   Mirror{Enabled: true},
		Storage:  Storage{DBPath: "shieldgate.db", PcapDir: "./pcap", PcapEnabled: false},
		API:      API{Listen: ":8080"},
		Board:    Board{Type: "forcad", PollInterval: 10 * time.Second},
	}
}

// Load reads configuration from path (yaml) with defaults and env override.
func Load(path string) (*Config, error) {
	v := viper.New()
	c := Defaults()
	v.SetConfigType("yaml")
	if path != "" {
		v.SetConfigFile(path)
		if err := v.ReadInConfig(); err != nil {
			return nil, fmt.Errorf("read config: %w", err)
		}
	}
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	if err := v.Unmarshal(c); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Config) Validate() error {
	if c.Optimize.BanFraction <= 0 || c.Optimize.BanFraction >= 1 {
		return fmt.Errorf("optimize.ban_fraction must be in (0,1), got %v", c.Optimize.BanFraction)
	}
	if c.Learn.RoundDuration <= 0 {
		return fmt.Errorf("learn.round_duration must be > 0")
	}
	switch c.Board.Type {
	case "forcad", "ctfd", "faust":
	default:
		return fmt.Errorf("board.type must be one of forcad|ctfd|faust, got %q", c.Board.Type)
	}
	if c.General.MaxPayload <= 0 {
		return fmt.Errorf("general.max_payload_bytes must be > 0")
	}
	return nil
}
