package mrte

import (
	"time"
)

const (
	MysqlReqSt_Init int32 = iota
	MysqlReqSt_Avail
	MysqlReqSt_Using
	MysqlReqSt_Deleting
)

const (
	MaxChangeMysqlReqStatusRetryCnt = 50
)

type MysqlRequestItem struct {
	//state int32
	Req *MysqlRequest
}

func (r *MysqlRequestItem) IsExpired(now time.Time, _timeoutSec int) bool {
	var (
		req *MysqlRequest
	)

	req = r.Req

	if r.Req == nil {
		return false
	}

	timeout := time.Duration(_timeoutSec) * time.Second
	if now.Sub(req.CapturedAt).Seconds() >= timeout.Seconds() {
		//timeout := time.Duration(_timeoutSec) * time.Millisecond
		//if now.Sub(req.CapturedAt).Milliseconds() > timeout.Milliseconds() {
		return true // expired
	}

	return false
}

type MysqlReqItemMap map[string]*MysqlRequestItem

func (m MysqlReqItemMap) AddItem(key string, req *MysqlRequest) *MysqlRequestItem {
	item := &MysqlRequestItem{Req: req}
	m[key] = item
	return item
}
