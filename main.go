package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/trivy-web-dash/frontend"
	redisx "github.com/trivy-web-dash/pkg/db/redis"
	"github.com/trivy-web-dash/pkg/logger"
	"github.com/trivy-web-dash/pkg/queue"
	scanner "github.com/trivy-web-dash/pkg/trivy/controller"
	"github.com/trivy-web-dash/pkg/trivy/handler"
	"github.com/trivy-web-dash/report"
	"github.com/trivy-web-dash/summary"

	trivy "github.com/trivy-web-dash/pkg/trivy"
)

func main() {

	aLog := logger.NewAppLogger("INFO")
	aLog.InitLogger()
	aLog.Info("Starting application with loglevel : INFO")
	redisURI, ok := os.LookupEnv("REDIS")
	if !ok {
		aLog.Fatal("REDIS is unset")
	}

	redisPass, ok := os.LookupEnv("REDIS_PASSWORD")
	if !ok {
		aLog.Info("REDIS_PASSWORD is unset, assuming no auth")
	}

	redisTLS, ok := os.LookupEnv("REDIS_TLS")
	if !ok {
		aLog.Info("REDIS_TLS is unset")
	}

	redisTLSkipVerify, ok := os.LookupEnv("REDIS_TLS_SKIP_VERIFY")
	if !ok {
		aLog.Info("REDIS_TLS_SKIP_VERIFY is unset")
	}

	trivyServer, ok := os.LookupEnv("TRIVY_SERVER")
	if !ok {
		log.Fatal("settrivy url in env TRIVY_SERVER")
	}

	tc := trivy.NewTrivyClient(aLog, trivyServer)

	bredisTLS, _ := strconv.ParseBool(redisTLS)
	bredisTLSkipVerify, _ := strconv.ParseBool(redisTLSkipVerify)

	pool, err := redisx.NewPool(redisURI, redisPass, "5", bredisTLS, bredisTLSkipVerify)
	if err != nil {
		aLog.Fatalf("unable to initialize redis pool: %v", err)
	}

	rstore := redisx.NewStore(pool)
	enqueuer := queue.NewEnqueuer(pool, rstore)
	controller := scanner.NewController(rstore, tc, aLog)
	worker := queue.NewWorker(pool, controller, aLog)

	backendHandler := handler.NewHandler(aLog, enqueuer, rstore)

	r := gin.Default()
	// frontend
	r.LoadHTMLGlob("./templates/*.html")
	r.Static("/assets", "./assets")
	r.Static("./templates/css", "./templates/css")
	r.GET("/", frontend.GetIndex())
	r.GET("/report/*image", frontend.GetReport())
	// r.POST("/summary", frontend.GetSummary())

	// backend
	r.POST("/scan/image", backendHandler.AcceptScanRequest)
	r.GET("/scan/status", backendHandler.GetScanStatus)
	r.GET("/scan/status/:id", backendHandler.GetScanStatusForJob)

	log.Println("initializing summary & report clients")
	if err := report.NewReportClient(redisURI, redisPass, bredisTLS, bredisTLSkipVerify, aLog); err != nil {
		log.Fatal("Failed to initialize report client: ", err)
	}

	if err := summary.NewSummaryClient(redisURI, redisPass, bredisTLS, bredisTLSkipVerify, aLog); err != nil {
		log.Fatal("Failed to initialize summary client: ", err)
	}

	log.Println("successfully initialized summary & report clients")

	httpServer := &http.Server{
		Addr:           ":" + "8001",
		Handler:        r,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}
	go func() {
		aLog.Infof("application server started on port : 8001")
		if err := httpServer.ListenAndServe(); err != nil {
			aLog.Fatal("server shutting down: %+v", err)
		}
	}()

	worker.Start()
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, os.Interrupt)

	<-quit

	ctx, shutdown := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdown()
	worker.Stop()
	if err := httpServer.Shutdown(ctx); err != nil {
		aLog.Fatalf("unable to start server: %v", err)
	}
}
