module github.com/cilium/state-writer

go 1.14

replace (
	github.com/miekg/dns => github.com/cilium/dns v1.1.4-0.20190417235132-8e25ec9a0ff3
	github.com/optiopay/kafka => github.com/cilium/kafka v0.0.0-20180809090225-01ce283b732b
	k8s.io/client-go => github.com/cilium/client-go v0.0.0-20200417200322-b77c886899ef
)

require (
	github.com/cilium/cilium v1.7.0-rc2.0.20200514072016-2d34336206d5
	github.com/sirupsen/logrus v1.4.2
)
