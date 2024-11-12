package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/trivy-web-dash/pkg/db"
	"github.com/trivy-web-dash/pkg/logger"
	"github.com/trivy-web-dash/pkg/queue"
)

type Handler struct {
	logger   logger.Logger
	enqueuer queue.Enqueuer
	store    db.Store
}

type ScanRequest struct {
	Image string `form:"image"`
}

func NewHandler(l logger.Logger, e queue.Enqueuer, s db.Store) *Handler {
	return &Handler{
		enqueuer: e,
		logger:   l,
		store:    s,
	}
}
func (h *Handler) AcceptScanRequest(c *gin.Context) {
	var req ScanRequest
	err := c.Bind(&req)
	if err != nil {
		h.logger.Errorf("unable to parse request : %s", err.Error())
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"status": "error parsing request"})
		return
	}

	if req.Image == "" {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid image name"})
		return
	}

	// validate image format and webhook url format
	h.logger.Infof("scan request for %s recieved result endpoint", req.Image)
	// add to queue
	j, err := h.enqueuer.Enqueue(req.Image)
	if err != nil {
		h.logger.Errorf("unable to queue request : %s", err.Error())
		c.AbortWithStatusJSON(http.StatusBadGateway, gin.H{"status": "error adding to queue"})
		return
	}

	// return id for job and 200 ok
	c.JSON(http.StatusOK, gin.H{"ID": j.ID})
}

func (h *Handler) GetScanStatus(c *gin.Context) {
	jobs, err := h.store.GetAllJobStatus()
	if err != nil {
		c.JSON(http.StatusInternalServerError,
			gin.H{"status": "error getting scan status"},
		)
		return
	}

	statusResponse := map[string]int{}
	for _, j := range jobs {
		statusResponse[j.Status.String()]++
	}

	c.JSON(http.StatusOK, statusResponse)
}

func (h *Handler) GetScanStatusForJob(c *gin.Context) {
	job, err := h.store.Get(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusInternalServerError,
			gin.H{"status": "error getting scan status"},
		)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"id":                    job.ID,
		"status":                job.Status.String(),
		"vulnerabilities_found": job.Report.TotalSeverities.Critical + job.Report.TotalSeverities.High + job.Report.TotalSeverities.Low + job.Report.TotalSeverities.Medium,
	})
}
