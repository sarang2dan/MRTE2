module github.com/kakao/MRTE2

go 1.18

require (
	github.com/globalsign/mgo v0.0.0-20181015135952-eeefdecb41b8
	github.com/go-sql-driver/mysql v1.6.0
	github.com/google/gopacket v1.1.19
	github.com/miekg/pcap v1.0.1
	golang.org/x/net v0.0.0-20190620200207-3b0461eec859
	golang.org/x/sys v0.0.0-20190412213103-97732733099d
	google.golang.org/appengine v1.6.7
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c
	gopkg.in/tomb.v2 v2.0.0-20161208151619-d5d1b5820637
	github.com/kr/pretty v0.2.1 // indirect
	github.com/kr/text v0.1.0 // indirect
)

replace (
	github.com/mikeg/pcap => ./MRTECollector/src/github.com/mikeg/pcap
)
