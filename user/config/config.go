package config

import (
	"github.com/spf13/viper"
)

type confInfo struct {
	Name string
	Type string
	Path string
}
type config struct {
	viper *viper.Viper
}

var (
	Conf *config
)

func init() {
	ci := confInfo{
		Name: "config",
		Type: "yaml",
		Path: "/Users/wangzhujia/Documents/学习资料/golang云原生/go_todolist/user/config/conf",
	}
	Conf = &config{getConf(ci)}
}
func getConf(ci confInfo) *viper.Viper {
	v := viper.New()
	v.SetConfigName(ci.Name)
	v.SetConfigType(ci.Type)
	v.AddConfigPath(ci.Path)
	v.ReadInConfig()

	return v
}

func (c *config) GetString(key string) string {
	return c.viper.GetString(key)
}
