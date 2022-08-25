package time

import (
	"time"
)

var currentTime time.Time

func GetCurrentTime() time.Time {
	return currentTime
}

func TimeTickerRoutine() {
	T := time.Tick(100 * time.Millisecond)
	for {
		select {
		case t := <-T:
			// todo: 메모리 배리어가 필요할 수 있음.
			currentTime = t
		}
	}
}
