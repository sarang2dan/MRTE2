//go:build linux

package mem

import (
	"errors"
	"fmt"
	"io/ioutil"
	"strconv"
	"syscall"
)

const (
	statm_size = iota
	statm_resident
	statm_share
	statm_text
	statm_lib
	statm_data
	statm_dt // over 2.6
	STATM_FIELD_END
)

// byte
func CheckMemoryUsage(limit int64) error {
	var residentMemory int64
	var procStatContents string
	pageSize := int64(syscall.Getpagesize())

	isOver = false

	if b, e := ioutil.ReadFile("/proc/self/statm"); e == nil {
		procStatContents = string(b)
	}

	fields := strings.Fields(procStatContents)
	if len(fields) >= (STATM_FIELD_END - 1) {
		if stat_value, e := strconv.ParseInt(fields[statm_resident], 10, 64); e == nil {
			residentMemory = stat_value * pageSize
		}
	}

	if residentMemory > limit {
		errStr := fmt.Sprint("Memory usage is too high (", residentMemory, " > ",
			limit, "), Increase memory limit or need to decrease memory usage")
		return errors.New(errStr)
	}

	return nil
}
