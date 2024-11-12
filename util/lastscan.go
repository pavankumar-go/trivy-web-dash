package util

import (
	"strconv"
	"time"
)

func ConvertToHumanReadable(t time.Duration) string {
	// if image scanned is more than 24 hours ago: 24h05m10s
	// convert it to show it in days format: 1 day ago

	lastScannedStr := t.String()
	if t.Hours() > 24 {
		lastScannedStr = strconv.Itoa(int(t.Hours())/24) + " day(s)"
	}

	return lastScannedStr
}
