package config

import (
	"os"
	"strconv"

	"gopkg.in/yaml.v2"
)

const (
	dbUserEnvName = "DB_USER"
	dbPwdEnvName  = "DB_PWD"
)

type Mysql struct {
	Host     string `yaml:"host"`
	Port     string `yaml:"port"`
	DB       string `yaml:"db"`
	User     string `yaml:"user"`
	Password string `yaml:"password"`
}

type FileDB struct {
	Path     string `yaml:"path"`
	TempPath string `yaml:"temp_path"`
}

type Server struct {
	GrpcAddr     string `yaml:"grpc_addr"`
	HttpAddr     string `yaml:"http_addr"`
	StartVersion int64  `yaml:"start_version"`
}

type Config struct {
	// Mysql 数据库消息
	Mysql Mysql `yaml:"mysql"`
	// FileDB 文件数据库信息
	FileDB FileDB `yaml:"file_db"`
	// 服务器设置
	Server Server `yaml:"server"`

	// 解密密钥, 不在配置文件, 通过启动时输入, 用于解密数据库中客户端输入信息
	EncryptKey []byte `yaml:"-"`
}

var conf *Config

func InitConfig() (Config, error) {
	var result Config

	configFile := "config.yml"
	if !fileExist(configFile) {
		return result, os.ErrNotExist
	}

	configInfo, err := os.ReadFile(configFile)
	if err != nil {
		return result, err
	}

	err = yaml.Unmarshal(configInfo, &result)

	conf = syncFromENV(&result)
	return result, err
}

func GetConfig() (Config, error) {
	if conf == nil {
		return InitConfig()
	}

	return *conf, nil
}

func SetEncryptKey(key []byte) {
	conf.EncryptKey = key
}

func fileExist(path string) bool {
	_, err := os.Stat(path)
	return err == nil || os.IsExist(err)
}

func syncFromENV(cfg *Config) *Config {
	mpcDBHost := os.Getenv("DB_HOST")
	if mpcDBHost != "" {
		cfg.Mysql.Host = mpcDBHost
	}

	mpcDBPort := os.Getenv("DB_PORT")
	if mpcDBPort != "" {
		cfg.Mysql.Port = mpcDBPort
	}

	mpcDBDatabase := os.Getenv("DATABASE")
	if mpcDBDatabase != "" {
		cfg.Mysql.DB = mpcDBDatabase
	}

	mpcDBUser := os.Getenv(dbUserEnvName)
	if mpcDBUser != "" {
		cfg.Mysql.User = mpcDBUser
	}

	mpcDBPass := os.Getenv(dbPwdEnvName)
	if mpcDBPass != "" {
		cfg.Mysql.Password = mpcDBPass
	}

	versionStr := os.Getenv("VERSION")
	if versionStr != "" {
		version, _ := strconv.Atoi(versionStr)
		cfg.Server.StartVersion = int64(version)
	}

	dirDBPath := os.Getenv("FILE_DB_PATH")
	if dirDBPath != "" {
		cfg.FileDB.Path = dirDBPath
	}

	return cfg
}
