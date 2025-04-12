package main

import (
	_ "github.com/apache/apisix-go-plugin-runner/cmd/go-runner/plugins"
	"github.com/apache/apisix-go-plugin-runner/pkg/log"
	"github.com/apache/apisix-go-plugin-runner/pkg/plugin"
	"github.com/apache/apisix-go-plugin-runner/pkg/runner"
	"github.com/apisix-go-runner-plugin/plugins"
	"go.uber.org/zap/zapcore"
)

func main() {
	cfg := runner.RunnerConfig{}
	cfg.LogLevel = zapcore.DebugLevel
	err := plugin.RegisterPlugin(&plugins.RequestInjectorPlugin{})
	if err != nil {
		log.Fatalf("failed to register plugin BasicAuthPlugin: %s", err)
	}
	runner.Run(cfg)
}
