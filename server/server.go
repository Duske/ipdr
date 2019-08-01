package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/miguelmota/ipdr/ipfs"
	"github.com/miguelmota/ipdr/regutil"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"net"
	"net/http"
	"strconv"
	"strings"
)

// Server is server structure
type Server struct {
	debug       bool
	listener    net.Listener
	host        string
	ipfsGateway string
	tlsCrtPath  string
	tlsKeyPath  string
}

// Config is server config
type Config struct {
	Debug       bool
	Port        uint
	IPFSGateway string
	TLSCrtPath  string
	TLSKeyPath  string
}

// InfoResponse is response for manifest info response
type InfoResponse struct {
	Info        string   `json:"what"`
	Project     string   `json:"project"`
	Gateway     string   `json:"gateway"`
	Handles     []string `json:"handles"`
	Problematic []string `json:"problematic"`
}

var projectURL = "https://github.com/miguelmota/ipdr"

var contentTypes = map[string]string{
	"manifestV2Schema":     "application/vnd.docker.distribution.manifest.v2+json",
	"manifestListV2Schema": "application/vnd.docker.distribution.manifest.list.v2+json",
}

// NewServer returns a new server instance
func NewServer(config *Config) *Server {
	if config == nil {
		config = &Config{}
	}

	var port uint = 5000
	if config.Port != 0 {
		port = config.Port
	}

	return &Server{
		host:        fmt.Sprintf("0.0.0.0:%v", port),
		debug:       config.Debug,
		ipfsGateway: ipfs.NormalizeGatewayURL(config.IPFSGateway),
		tlsCrtPath:  config.TLSCrtPath,
		tlsKeyPath:  config.TLSKeyPath,
	}
}

// Start runs the registry server
func (s *Server) Start() error {
	//  return if already started
	if s.listener != nil {
		return nil
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		uri := r.RequestURI
		s.Debugf("[registry/server] %s", uri)

		if uri == "/health" {
			fmt.Fprintln(w, "OK")
			return
		}

		if uri == "/v2/" {
			jsonstr, err := json.Marshal(&InfoResponse{
				Info:    "An IPFS-backed Docker registry",
				Project: projectURL,
				Gateway: s.ipfsGateway,
				Handles: []string{
					contentTypes["manifestListV2Schema"],
					contentTypes["manifestV2Schema"],
				},
				Problematic: []string{"version 1 registries"},
			})
			if err != nil {
				fmt.Fprintln(w, err)
				return
			}

			w.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
			fmt.Fprintln(w, string(jsonstr))
			return
		}

		if len(uri) <= 1 {
			fmt.Fprintln(w, "invalid multihash")
			return
		}

		var suffix string
		if strings.HasSuffix(uri, "/latest") {
			// docker daemon requesting the manifest
			suffix = "-v1"
			// If multiple mediaTypes in Accept-Header cannot be resolved to an array split it by ','
			accepts := r.Header["Accept"]
			if len(accepts) == 1 && strings.Contains(accepts[0], ",") {
				accepts = strings.Split(accepts[0], ",")
			}
			for _, accept := range accepts {
				if accept == contentTypes["manifestV2Schema"] ||
					accept == contentTypes["manifestListV2Schema"] {
					suffix = "-v2"
					break
				}
			}
		}

		parts := strings.Split(uri, "/")
		if len(parts) <= 2 {
			fmt.Fprintln(w, "out of range")
			return
		}

		hash := regutil.IpfsifyHash(parts[2])
		rest := strings.Join(parts[3:], "/") // tag
		path := hash + "/" + rest
		var digest = ""
		if parts[3] == "manifests" && strings.HasPrefix(parts[4], "sha256") {
			digest = parts[4]
			path = hash + "/manifests/latest-v2"
		}
		accepts := r.Header["Accept"]
		contentType := "application/vnd.docker.distribution.manifest.v2+json"
		if parts[3] == "blobs" && strings.Contains(accepts[0], "application/vnd.docker.container.image.v1+json") {
			digest = parts[4]
			path = hash + "/blobs/" + digest + "/" + strings.TrimPrefix(digest, "sha256:") + ".json"
			contentType = "application/vnd.docker.container.image.v1+json"
		}

		bin := false
		if parts[3] == "blobs" && strings.Contains(accepts[0], "application/vnd.docker.image.rootfs.diff.tar.gzip") {
			digest = parts[4]
			contentType = "application/octet-stream"
			bin = true
		}
		// blob request
		location := s.ipfsURL(path)

		if suffix != "" {
			// manifest request
			location = location + suffix
		}
		s.Debugf("[registry/server] location %s", location)

		req, err := http.NewRequest("GET", location, nil)
		if err != nil {
			fmt.Fprintf(w, err.Error())
			return
		}

		httpClient := http.Client{}
		resp, err := httpClient.Do(req)
		if err != nil {
			fmt.Fprintf(w, err.Error())
			return
		}

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			fmt.Fprintf(w, err.Error())
			return
		}
		aha := string(body)
		if digest == "" {
			var f = ""
			f, err = Sha256Text(aha)
			digest = "sha256:"+f
		}
		if err != nil {
			fmt.Fprintf(w, err.Error())
			return
		}
		//w.Header().Set("Location", location) // not required since we're fetching the content and proxying
		w.Header().Set("Docker-Content-Digest", digest)
		w.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
		// if latest-v2 set header
		w.Header().Set("Content-Type", contentType)

		if bin {
			w.Write(body)
		} else {
			w.Header().Set("Content-Length", strconv.Itoa(len(aha)))
				fmt.Fprintf(w, aha)
		}

	})

	var err error
	s.listener, err = net.Listen("tcp", s.host)
	if err != nil {
		return err
	}

	s.Debugf("[registry/server] listening on %s", s.listener.Addr())
	if s.tlsKeyPath != "" && s.tlsCrtPath != "" {
		return http.ServeTLS(s.listener, nil, s.tlsCrtPath, s.tlsKeyPath)
	}
	return http.Serve(s.listener, nil)
}

// Stop stops the server
func (s *Server) Stop() {
	if s.listener != nil {
		s.listener.Close()
	}
}

// Debugf prints debug log
func (s *Server) Debugf(str string, args ...interface{}) {
	if s.debug {
		log.Printf(str, args...)
	}
}

// ipfsURL returns the full IPFS url
func (s *Server) ipfsURL(hash string) string {
	return fmt.Sprintf("%s/ipfs/%s", s.ipfsGateway, hash)
}

// sha256 returns the sha256 hash of a string
func Sha256Text(text string) (string, error) {
	bv := []byte(text)
	hash := sha256.Sum256(bv)

	return hex.EncodeToString(hash[:]), nil
}

// sha256 returns the sha256 hash of a string
func Sha256Byte(content []byte) (string, error) {
	hash := sha256.Sum256(content)

	return hex.EncodeToString(hash[:]), nil
}