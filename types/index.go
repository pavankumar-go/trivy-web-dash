package types

type IndexData struct {
	Title               string         `json:"title"`
	TotalSeverities     Severities     `json:"totalSeverities"`
	ScanStatus          map[string]int `json:"scanStatus"`
	Summary             []Summary      `json:"summary"`
	TotalImages         int
	TotalVulnerabilties int
}

type Severities struct {
	Critical int
	High     int
	Medium   int
	Low      int
}
