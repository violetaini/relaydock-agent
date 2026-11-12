package chitanda

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestReviewClientPSKDecryptsServerTickets(t *testing.T) {
	cfg, e := buildServerTLSConfig(testTLSConfig(t, &InboundConfig{Psk: string(reviewKey), StrictSni: "localhost"}))
	if e != nil {
		t.Fatal(e)
	}
	cert, e := x509.ParseCertificate(cfg.Certificates[0].Certificate[0])
	if e != nil {
		t.Fatal(e)
	}
	t.Logf("default public certificate organization=%v", cert.Subject.Organization)
	captured := make(chan []byte, 8)
	srvCfg := cfg.Clone()
	srvCfg.NextProtos = []string{"http/1.1"}
	srvCfg.WrapSession = func(cs tls.ConnectionState, ss *tls.SessionState) ([]byte, error) {
		ticket, e := cfg.EncryptTicket(cs, ss)
		if e == nil {
			select {
			case captured <- ticket:
			default:
			}
		}
		return ticket, e
	}
	hs := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }))
	hs.TLS = srvCfg
	hs.StartTLS()
	defer hs.Close()
	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: "localhost", MinVersion: tls.VersionTLS13, ClientSessionCache: tls.NewLRUClientSessionCache(1)}}}
	defer hc.CloseIdleConnections()
	res, e := hc.Get(hs.URL)
	if e != nil {
		t.Fatal(e)
	}
	io.Copy(io.Discard, res.Body)
	res.Body.Close()
	ticket := recvReview(t, captured)
	var key [32]byte
	copy(key[:], reviewKey[:32])
	outsider := new(tls.Config)
	outsider.SetSessionTicketKeys([][32]byte{key})
	state, e := outsider.DecryptTicket(ticket, tls.ConnectionState{})
	if e != nil {
		t.Fatal(e)
	}
	if state != nil {
		t.Error("a holder of client PSK can decrypt server-only session ticket state")
	}
}
