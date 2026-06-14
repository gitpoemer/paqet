package run

import (
	"log"
	"os"
	"paqet/internal/conf"
	"paqet/internal/flog"
	"paqet/internal/pkg/buffer"
	"runtime/debug"

	"github.com/spf13/cobra"
)

var confPath string

func init() {
	Cmd.Flags().StringVarP(&confPath, "config", "c", "config.yaml", "Path to the configuration file.")
}

var Cmd = &cobra.Command{
	Use:   "run",
	Short: "Runs the client or server based on the config file.",
	Long:  `The 'run' command reads the specified YAML configuration file.`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg, err := conf.LoadFromFile(confPath)
		if err != nil {
			log.Fatalf("Failed to load configuration: %v", err)
		}
		initialize(cfg)

		switch cfg.Role {
		case "client":
			startClient(cfg)
			return
		case "server":
			startServer(cfg)
			return
		}

		log.Fatalf("Failed to load configuration")
	},
}

func initialize(cfg *conf.Conf) {
	flog.SetLevel(cfg.Log.Level)
	buffer.Initialize(cfg.Transport.TCPBuf, cfg.Transport.UDPBuf)
	applyGOMEMLIMIT()
}

// applyGOMEMLIMIT sets a soft memory limit so the Go GC pages more
// aggressively before the kernel OOM-kills paqet. Honors an explicit
// GOMEMLIMIT env var if set; otherwise picks 90% of cgroup-or-host RAM.
//
// Why default-on: at 30k-user scale paqet's heap can grow past 8 GB
// from smux buffers + per-stream state. The Go GC default trigger
// (GOGC=100) means we wait until heap doubles to GC — easily a 4 GB
// → 8 GB → kernel OOM cascade. GOMEMLIMIT trades extra CPU on GC for
// graceful soft-fail.
func applyGOMEMLIMIT() {
	if v := os.Getenv("GOMEMLIMIT"); v != "" {
		// User set it explicitly; runtime already honored it at
		// process start. Don't touch.
		flog.Infof("GOMEMLIMIT honored from env: %s", v)
		return
	}
	available := readCgroupOrHostMemBytes()
	if available <= 0 {
		return
	}
	limit := int64(float64(available) * 0.90)
	debug.SetMemoryLimit(limit)
	flog.Infof("GOMEMLIMIT defaulted to 90%% of available memory: %d MB (of %d MB)",
		limit/(1<<20), available/(1<<20))
}
