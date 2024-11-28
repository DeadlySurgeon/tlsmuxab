package main

import (
	"concepts/tlsmuxab/services"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() (err error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	wg := &sync.WaitGroup{}

	for _, service := range []services.Service{
		services.Alpha,
		services.Beta,
		services.Delta,
		services.Gamma,
		services.Epsilon,
	} {

		if err = startServer(ctx, wg, service); err != nil {
			cancel()
			wg.Wait()
			return err
		}
	}

	sigWait() // wait for termination on user behalf
	cancel()  // tell the servers to stop
	wg.Wait() // wait for them to wrap up

	return nil
}

func startServer(ctx context.Context, wg *sync.WaitGroup, service services.Service) error {
	port := service.Port()
	if port == 0 {
		return fmt.Errorf("No entry in port map for %s", service)
	}

	cw, err := newCertWatcher(service)
	if err != nil {
		return err
	}

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: setupServiceMux(service),
		TLSConfig: &tls.Config{
			GetCertificate: cw.getCert,
			ClientCAs:      rootCaPool,
			ClientAuth:     tls.RequireAndVerifyClientCert,
		},
	}

	wg.Add(1)
	go func() {
		defer wg.Done()

		go cw.start()
		defer cw.watcher.Close()

		go func() {
			<-ctx.Done()
			_ = server.Close()
		}()
		fmt.Println("Starting up", service, "on port", port)
		if err := server.ListenAndServeTLS("", ""); err != nil {
			fmt.Println(service, "closed:", err)
			return
		}
	}()

	return nil
}

var rootCaPool = func() *x509.CertPool {
	pool := x509.NewCertPool()

	for _, certPath := range []string{
		"certs/ca/root-ca-cert.pem",
		"certs/ca/intermediate-ca-cert.pem",
	} {
		certBytes, err := os.ReadFile(certPath)
		if err != nil {
			panic("unable to read " + certPath + ": " + err.Error())
		}
		if ok := pool.AppendCertsFromPEM(certBytes); !ok {
			panic("failed to load " + certPath)
		}
	}

	return pool
}()

func setupServiceMux(service services.Service) *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(rw http.ResponseWriter, r *http.Request) {
		byts, err := json.MarshalIndent(serviceHello{
			Service: string(service),
			Message: fmt.Sprintf("%s greets you%s", service, getCommonName(r)),
			Time:    time.Now(),
		}, "", "  ")
		if err != nil {
			http.Error(rw, "failed to marshal hello: "+err.Error(), http.StatusInternalServerError)
		}

		_, _ = rw.Write(byts)
	})

	return mux
}

func getCommonName(r *http.Request) string {
	return ", " + r.TLS.PeerCertificates[0].Subject.CommonName
}

type serviceHello struct {
	Service string    `json:"service"`
	Message any       `json:"message"`
	Time    time.Time `json:"time"`
}

func sigWait() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	<-c
	signal.Stop(c)
}

type certWatcher struct {
	service  services.Service
	watcher  *fsnotify.Watcher
	certLock sync.RWMutex
	cert     tls.Certificate
}

func newCertWatcher(service services.Service) (*certWatcher, error) {
	cert, err := service.Cert()
	if err != nil {
		return nil, fmt.Errorf("failed to load service cert: %v", err)
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	if err := watcher.Add(service.KeyPath()); err != nil {
		return nil, err
	}

	return &certWatcher{
		service: service,
		watcher: watcher,
		cert:    cert,
	}, nil
}

func (cw *certWatcher) start() {
	var err error
	for event := range cw.watcher.Events {
		time.Sleep(100 * time.Millisecond)
		fmt.Println(cw.service, event.Name)
		if !strings.HasSuffix(event.Name, cw.service.KeyPath()) {
			continue
		}
		func() {
			cw.certLock.Lock()
			defer cw.certLock.Unlock()
			fmt.Println("Reloading Cert/Key for", cw.service)
			if cw.cert, err = cw.service.Cert(); err != nil {
				fmt.Println(cw.service, err)
			}
		}()
	}
}

func (cw *certWatcher) getCert(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
	cw.certLock.RLock()
	defer cw.certLock.RUnlock()
	cert := cw.cert
	return &cert, nil
}
