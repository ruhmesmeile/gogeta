package main

import (
	"log"
	"errors"
	"flag"
	"github.com/coreos/go-etcd/etcd"
	"github.com/golang/glog"
)

type Config struct {
	port               int
	domainPrefix       string
	servicePrefix      string
	etcdAddress        string
	resolverType       string
	templateDir        string
	lastAccessInterval int
	client             *etcd.Client
	forceFwSsl         bool
	UrlHeaderParam     string
	cpuProfile         string
	tls 							 bool
	cert               string
	key                string
	ca                 string
}

func (c *Config) getEtcdClient() (*etcd.Client, error) {
	if c.client == nil {
		if c.tls {
			err := errors.New("Empty error");
			c.client, err = etcd.NewTLSClient([]string{c.etcdAddress}, c.cert, c.key, c.ca)

			if err != nil {
				return nil, errors.New("Unable to create TLS client for etcd2, check your credential files")
			}
		} else {
			c.client = etcd.NewClient([]string{c.etcdAddress})
		}
		if !c.client.SyncCluster() {
			return nil, errors.New("Unable to sync with etcd cluster, check your configuration or etcd status")
		}
	}
	return c.client, nil
}

func parseConfig() *Config {
	config := &Config{}
	flag.IntVar(&config.port, "port", 7777, "Port to listen")
	flag.StringVar(&config.domainPrefix, "domainDir", "/domains", "etcd prefix to get domains")
	flag.StringVar(&config.servicePrefix, "serviceDir", "/services", "etcd prefix to get services")
	flag.StringVar(&config.etcdAddress, "etcdAddress", "http://127.0.0.1:4001/", "etcd client host")
	flag.StringVar(&config.resolverType, "resolverType", "IoEtcd", "type of resolver (IoEtcd|Env|Dummy)")
	flag.StringVar(&config.templateDir, "templateDir", "./templates", "Template directory")
	flag.StringVar(&config.UrlHeaderParam, "UrlHeaderParam", "", "Name of the param to inject the originating url")
	flag.IntVar(&config.lastAccessInterval, "lastAccessInterval", 10, "Interval (in seconds to refresh last access time of a service")
	flag.BoolVar(&config.forceFwSsl, "forceFwSsl", false, "If not x-forwarded-proto set to https, then redirecto to the equivalent https url")
	flag.StringVar(&config.cpuProfile, "cpuProfile", "/tmp/gogeta.prof", "File to dump cpuProfile")
	flag.BoolVar(&config.tls, "tls", false, "Enable etcd2 client TLS")
	flag.StringVar(&config.cert, "cert", "/etc/ssl/certs/cert.pem", "Client certificate for TLS-secured etcd2 communication")
	flag.StringVar(&config.key, "key", "/etc/ssl/certs/key.pem", "Client key for TLS-secured etcd2 communication")
	flag.StringVar(&config.ca, "ca", "/etc/ssl/certs/ca.pem", "CA certificate for TLS-secured etcd2 communication")
	flag.Parse()

	glog.Infof("Dumping Configuration")
	glog.Infof("  listening port : %d", config.port)
	glog.Infof("  domainPrefix : %s", config.domainPrefix)
	glog.Infof("  servicesPrefix : %s", config.servicePrefix)
	glog.Infof("  etcdAddress : %s", config.etcdAddress)
	glog.Infof("  resolverType : %s", config.resolverType)
	glog.Infof("  templateDir: %s", config.templateDir)
	glog.Infof("  lastAccessInterval: %d", config.lastAccessInterval)
	glog.Infof("  forceFwSsl: %t", config.forceFwSsl)
	glog.Infof("  UrlHeaderParam: %s", config.UrlHeaderParam)
	glog.Infof("  cpuProfile: %s", config.cpuProfile)
	glog.Infof("  tls: %s", config.tls)
	glog.Infof("  cert: %s", config.cert)
	glog.Infof("  key: %s", config.key)
	glog.Infof("  ca: %s", config.ca)

	return config
}