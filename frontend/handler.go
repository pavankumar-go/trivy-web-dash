package frontend

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/trivy-web-dash/report"
	"github.com/trivy-web-dash/scan"
	"github.com/trivy-web-dash/summary"
	"github.com/trivy-web-dash/types"
	"github.com/trivy-web-dash/util"
)

func GetReport() gin.HandlerFunc {
	return func(c *gin.Context) {
		image, _ := c.Params.Get("image")
		log.Println("getting report for image:", image)

		r, ttl, err := report.GetReportClient().Get(c, image)
		if err != nil {
			log.Fatalf("REDIS REPORT GET - %v", err)
		}

		totalCritical, totalHigh, totalMedium, totalLow := 0, 0, 0, 0
		for _, r := range r.Results {
			for _, v := range r.Vulnerabilities {
				if v.Severity == "CRITICAL" {
					totalCritical++
				}
				if v.Severity == "HIGH" {
					totalHigh++
				}
				if v.Severity == "MEDIUM" {
					totalMedium++
				}
				if v.Severity == "LOW" {
					totalLow++
				}
			}
		}

		report := types.Report{
			Results: r.Results,
			TotalSeverities: types.Severities{
				Critical: totalCritical,
				High:     totalHigh,
				Medium:   totalMedium,
				Low:      totalLow,
			},
			LastScanAt: util.ConvertToHumanReadable((2000 * time.Hour) - ttl),
		}
		c.HTML(http.StatusOK, "report.html", report)
	}
}

func GetIndex() gin.HandlerFunc {
	return func(c *gin.Context) {
		summaries, err := summary.GetSummaryClient().GetAll(c)
		if err != nil {
			log.Fatalf("Summary: REDIS GETALL: %v", err)
		}

		totalCritical, totalHigh, totalMed, totalLow, totalImages := 0, 0, 0, 0, 0
		for i, s := range summaries {
			summaries[i].Image = strings.TrimPrefix(s.Image, "vulndb/")
			totalCritical += s.VSummary["CRITICAL"]
			totalHigh += s.VSummary["HIGH"]
			totalMed += s.VSummary["MEDIUM"]
			totalLow += s.VSummary["LOW"]
			totalImages++
		}

		scanstatusBytes, err := scan.GetScanStatus("http://localhost:8001/scan/status")
		if err != nil {
			log.Println("error getting scan status: ", err)
		}

		scanStatusMap := make(map[string]int)
		json.Unmarshal(scanstatusBytes, &scanStatusMap)

		indexData := &types.IndexData{
			Title:   "VulnDB",
			Summary: summaries,
			TotalSeverities: types.Severities{
				Critical: totalCritical,
				High:     totalHigh,
				Medium:   totalMed,
				Low:      totalLow,
			},
			ScanStatus:          scanStatusMap,
			TotalImages:         totalImages,
			TotalVulnerabilties: totalCritical + totalHigh + totalMed + totalLow,
		}

		c.HTML(http.StatusOK, "index.html", indexData)
	}
}
