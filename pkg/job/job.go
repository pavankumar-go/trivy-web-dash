package job

import "github.com/trivy-web-dash/types"

type ScanJobStatus int

const (
	Queued ScanJobStatus = iota
	Pending
	Scanned
	ScanFail
	WebhookFail
	Done
)

func (s ScanJobStatus) String() string {
	if s < 0 || s > 5 {
		return "Unknown"
	}
	return [...]string{"Queued", "Pending", "Scanned", "ScanFail", "WebhookFail", "Done"}[s]
}

type ScanJob struct {
	ID      string        `json:"id"`
	Status  ScanJobStatus `json:"status"`
	Error   string        `json:"error"`
	Report  types.Report  `json:"report"`
	Webhook string        `json:"webhook"`
}
