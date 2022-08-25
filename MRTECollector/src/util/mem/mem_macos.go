//go:build darwin

package mem

// https://developer.apple.com/library/Mac/qa/qa1398/_index.html

/*
#include <mach/mach.h>
#include <mach/task_info.h>
#include <mach/mach_time.h>
#include <sys/sysctl.h>


int get_process_info(struct kinfo_proc *kp, pid_t pid)
{
	size_t len = sizeof(struct kinfo_proc);
	static int name[] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, 0 };
	name[3] = pid;
	kp->kp_proc.p_comm[0] = '\0'; // jic
	return sysctl((int *)name, sizeof(name)/sizeof(*name), kp, &len, NULL, 0);
}
uint64_t absolute_to_nano(uint64_t abs)
{
	static mach_timebase_info_data_t s_timebase_info;

	if (s_timebase_info.denom == 0) {
		(void) mach_timebase_info(&s_timebase_info);
	}

        return (uint64_t)((abs * s_timebase_info.numer) / (s_timebase_info.denom));
}
*/
import "C"

import (
	"errors"
	"fmt"
	log "github.com/sirupsen/logrus"
	"os"
	"reflect"
	"unsafe"
)

func CheckMemoryUsage(limit int64) error {
	var residentMemory float64

	_, residentMemory, _ = collectMemInfo()

	if int64(residentMemory) > limit {
		errStr := fmt.Sprint("Memory usage is too high (", residentMemory, " > ",
			limit, "), Increase memory limit or need to decrease memory usage")
		return errors.New(errStr)
	}

	return nil
}

var hport C.host_t

func init() {
	hport = C.host_t(C.mach_host_self())
}

// Collect walks through /proc and updates stats
// Collect is usually called internally based on
// parameters passed via metric context
// reference /usr/include/mach/task_info.h
// works on MacOSX 10.9.2; YMMV might vary
func collectMemInfo() (VirtualSize, ResidentSize, ResidentSizeMax float64) {
	var pDefaultSet C.processor_set_name_t
	var pDefaultSetControl C.processor_set_t
	var tasks C.task_array_t
	var taskCount C.mach_msg_type_number_t

	if C.processor_set_default(hport, &pDefaultSet) != C.KERN_SUCCESS {
		return
	}

	// get privileged port to get information about all tasks

	if C.host_processor_set_priv(C.host_priv_t(hport),
		pDefaultSet, &pDefaultSetControl) != C.KERN_SUCCESS {
		return
	}

	if C.processor_set_tasks(pDefaultSetControl, &tasks, &taskCount) != C.KERN_SUCCESS {
		return
	}

	// convert tasks to a Go slice
	hdr := reflect.SliceHeader{
		Data: uintptr(unsafe.Pointer(tasks)),
		Len:  int(taskCount),
		Cap:  int(taskCount),
	}

	goTaskList := *(*[]C.task_name_t)(unsafe.Pointer(&hdr))

	curpid := os.Getpid()

	// mach_msg_type_number_t - type natural_t = uint32_t
	var i uint32
	for i = 0; i < uint32(taskCount); i++ {
		taskID := goTaskList[i]
		var pid C.int
		// var tinfo C.task_info_data_t
		var count C.mach_msg_type_number_t
		var taskBasicInfo C.mach_task_basic_info_data_t

		if C.pid_for_task(C.mach_port_name_t(taskID), &pid) != C.KERN_SUCCESS {
			continue
		}

		if int(pid) == curpid {
			count = C.MACH_TASK_BASIC_INFO_COUNT
			kr := C.task_info(taskID, C.MACH_TASK_BASIC_INFO,
				(C.task_info_t)(unsafe.Pointer(&taskBasicInfo)),
				&count)
			if kr != C.KERN_SUCCESS {
				log.Fatalf("Fail to get task info: [pid=%d]", int(pid))
				/* exit */
				break
			}

			VirtualSize = float64(taskBasicInfo.virtual_size)
			ResidentSize = float64(taskBasicInfo.resident_size)
			ResidentSizeMax = float64(taskBasicInfo.resident_size_max)
			break
		}
	}

	return
}
