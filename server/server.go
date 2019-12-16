package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/julienschmidt/httprouter"
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
var DEFAULT_MANIFEST_PATH = "/manifests/latest-v2"

var contentTypes = map[string]string{
	"manifestV2Schema":     "application/vnd.docker.distribution.manifest.v2+json",
	"manifestListV2Schema": "application/vnd.docker.distribution.manifest.list.v2+json",
	"blobImageRootFSSchema": "application/vnd.docker.image.rootfs.diff.tar.gzip",
	"blobContainerConfigSchema": "application/vnd.docker.container.image.v1+json",
	"OCI_manifestV2Schema":     "application/vnd.oci.image.index.v1+json",
	"OCI_manifestListV2Schema": "application/vnd.oci.image.manifest.v1+json",
	"OCI_blobImageRootFSSchema": "application/vnd.oci.image.layer.v1.tar+gzip",
	"OCI_blobContainerConfigSchema": "application/vnd.oci.image.config.v1+json",
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

	getManifest := func (w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		ipfsHash := regutil.IpfsifyHash(ps.ByName("hash"))
		manifestVersion := ps.ByName("version")
		acceptHeader := r.Header.Get("Accept")
		validAcceptHeader := false
		var location = ""
		if headerAccepts(acceptHeader, contentTypes["manifestV2Schema"]) || headerAccepts(acceptHeader, contentTypes["manifestListV2Schema"]) {
			validAcceptHeader = true
			// for docker, always resolve to latest-v2 manifest
			location = s.ipfsURL(ipfsHash + DEFAULT_MANIFEST_PATH)
		}

		if headerAccepts(acceptHeader, contentTypes["OCI_manifestListV2Schema"]) || headerAccepts(acceptHeader, contentTypes["OCI_manifestV2Schema"]) {
			validAcceptHeader = true
			// default manifest
			suffix := DEFAULT_MANIFEST_PATH
			// specific manifest
			if strings.HasPrefix(manifestVersion, "/sha256:"){
				suffix = "/blobs" + manifestVersion
			}
			location = s.ipfsURL(ipfsHash + suffix)
		}
		if !validAcceptHeader {
			w.WriteHeader(400)
			fmt.Fprintf(w, "Only Registry schema v2 supported")
			return
		}

		body, err := requestFromGateway(location)
		if err != nil {
			fmt.Fprintf(w, err.Error())
			return
		}
		hash, _ := Sha256Byte(body)
		digest := "sha256:"+hash

		w.Header().Set("Docker-Content-Digest", digest)
		w.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
		w.Header().Set("Content-Type", getContentTypeForManifest(body))
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.Write(body)
	}

	getBlob := func (w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		ipfsHash := regutil.IpfsifyHash(ps.ByName("hash"))
		sha256Hash := ps.ByName("sha256Hash")
		acceptHeader := r.Header.Get("Accept")
		contentType := ""
		location := ""
		// blob config file
		if headerAccepts(acceptHeader, contentTypes["blobContainerConfigSchema"]) {
			// IPDR quirk: the config file lies in the blob directory as JSON-file in a directory named by the hash
			// e.g. hash=123, location -> /blobs/sha256:123/123.json
			path :=  "/blobs/" + sha256Hash + "/" + strings.TrimPrefix(sha256Hash, "sha256:") + ".json"
			location = s.ipfsURL(ipfsHash + path)
			contentType = contentTypes["blobContainerConfigSchema"]
		}
		// blob config file OCI
		if headerAccepts(acceptHeader, contentTypes["OCI_blobContainerConfigSchema"]) {
			path :=  "/blobs/" + sha256Hash
			location = s.ipfsURL(ipfsHash + path)
			contentType = contentTypes["blobContainerConfigSchema"]
		}

		// blob binary file
		if headerAccepts(acceptHeader, contentTypes["blobImageRootFSSchema"]) ||  headerAccepts(acceptHeader, contentTypes["OCI_blobImageRootFSSchema"]) {
			location = s.ipfsURL(ipfsHash + "/blobs/" + sha256Hash)
			contentType = "application/octet-stream"
		}
		body, err := requestFromGateway(location)
		if err != nil {
			fmt.Fprintf(w, err.Error())
			return
		}
		w.Header().Set("Docker-Content-Digest", sha256Hash)
		w.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.Write(body)
	}

	getStatus := func (w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
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

	getHealth := func (w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		fmt.Fprintln(w, "OK")
		return
	}

	router := httprouter.New()
	router.GET("/v2/", getStatus)
	router.GET("/health", getHealth)
	router.GET("/v2/:hash/manifests/*version", getManifest)
	router.GET("/v2/:hash/blobs/:sha256Hash", getBlob)

	var err error
	s.listener, err = net.Listen("tcp", s.host)
	if err != nil {
		return err
	}

	s.Debugf("[registry/server] listening on %s", s.listener.Addr())
	if s.tlsKeyPath != "" && s.tlsCrtPath != "" {
		return http.ServeTLS(s.listener, router, s.tlsCrtPath, s.tlsKeyPath)
	}
	return http.Serve(s.listener, router)
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

func headerAccepts(acceptHeader string, mediaType string) bool {
	var acceptedTypes []string
	if strings.Contains(acceptHeader, ",") {
		acceptedTypes = strings.Split(acceptHeader, ",")
	} else {
		return acceptHeader == mediaType
	}
	for _, accept := range acceptedTypes {
		if strings.TrimSpace(accept) == mediaType {
			return true
		}
	}
	return false
}

func getContentTypeForManifest(manifest []byte) string {
	jsonMap := make(map[string]interface{})
	err := json.Unmarshal(manifest, &jsonMap)
	if err != nil {
		panic(err)
	}
	var contentType = jsonMap["mediaType"].(string)
	if contentType != "" {
		return contentType
	}
	return contentTypes["manifestV2Schema"]
}

func Sha256Byte(content []byte) (string, error) {
	hash := sha256.Sum256(content)
	return hex.EncodeToString(hash[:]), nil
}

func requestFromGateway(url string) ([]byte, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	httpClient := http.Client{}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return body, nil
}