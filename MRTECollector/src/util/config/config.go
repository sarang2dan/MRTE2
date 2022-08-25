package config

import (
	"flag"
)

// ------------------
// Application Parameters
var (
	_iface   = flag.String("interface", "eth0", "Interface to get packets from")
	_snaplen = flag.Int("snaplen", 65536, "SnapLen for pcap packet capture")
	_port    = flag.Int("port", 3306, "Port to get packets from")
	// var filter = flag.String("filter", "tcp dst port 3306", "BPF filter for pcap")
	_onlySelect                 = flag.Bool("onlyselect", true, "relay only select statement")
	_packetExpireTimeoutSeconds = flag.Int("packetexpire", 10, "Packet expire timeout seconds")
	_fastPacketParsing          = flag.Bool("fastparsing", true, "Filter-out no-application payload packet and use custom packet parser")
	_threads                    = flag.Int("threads", 5, "Assembler threads")
	_mongo_uri                  = flag.String("mongouri", "mongodb://127.0.0.1:27017?connect=direct", "MongoDB server connection uri")
	_mongo_db                   = flag.String("mongodb", "mrte", "MongoDB DB name")
	_mongo_collection           = flag.String("mongocollection", "mrte", "MongoDB collection name prefix")
	// mongo_collections = threads
	// var mongo_collections = flag.Int("mongocollections", 5, "MongoDB collection partition count")
	_mongo_capped_size = flag.Int("mongocollectionsize", 50*1024*1024, "MongoDB capped-collection max-bytes")
	// MySQL Server connection url for select default database of all connection
	_mysql_uri      = flag.String("mysqluri", "userid:password@tcp(127.0.0.1:3306)/", "MySQL server connection uri")
	_logAllPackets  = flag.Bool("verbose", false, "Log whenever we see a packet")
	_UseGoPcap      = flag.Bool("use-go-pcap", false, "relay only select statement")
	_Debugging      = flag.Bool("debug", false, "Debugging")
	_LogEnableColor = flag.Bool("log-enable-color", true, "enable coloring log (default:true)")
	_LogLevel       = flag.String("log-level", "info", "Print log level: one of [debug|info|warn|error|fatal] (default \"info\")")
)

type Config struct {
	Iface                      string
	Snaplen                    int
	Port                       int
	OnlySelect                 bool
	PacketExpireTimeoutSeconds int
	FastPacketParsing          bool
	Threads                    int
	Mongo_uri                  string
	Mongo_db                   string
	Mongo_collection           string
	Mongo_capped_size          int
	Mysql_uri                  string
	LogAllPackets              bool
	UseGoPcap                  bool
	Debugging                  bool
	LogEnableColor             bool
	LogLevel                   string
}

var DefaultConfig Config

func GetDefaultConfig() *Config {
	return &DefaultConfig
}

func (c *Config) Load() {
	c.Iface = *_iface
	c.Snaplen = *_snaplen
	c.Port = *_port
	c.OnlySelect = *_onlySelect
	c.PacketExpireTimeoutSeconds = *_packetExpireTimeoutSeconds
	c.FastPacketParsing = *_fastPacketParsing
	c.Threads = *_threads
	c.Mongo_uri = *_mongo_uri
	c.Mongo_db = *_mongo_db
	c.Mongo_collection = *_mongo_collection
	c.Mongo_capped_size = *_mongo_capped_size
	c.Mysql_uri = *_mysql_uri
	c.LogAllPackets = *_logAllPackets
	c.UseGoPcap = *_UseGoPcap
	c.Debugging = *_Debugging
	c.LogEnableColor = *_LogEnableColor
	c.LogLevel = *_LogLevel
}
