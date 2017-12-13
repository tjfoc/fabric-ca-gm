package lib

import (
	"fmt"
	"math/rand"
	"os"
	"path"
	"strconv"
	"testing"

	"github.com/cloudflare/cfssl/log"
	"github.com/tjfoc/gmsm/sm2"
)

const (
	rootPort         = 7075
	rootDir          = "rootDir"
	intermediatePort = 7076
	intermediateDir  = "intDir"
	testdataDir      = "../testdata"
)

func getRootServerURL() string {
	return fmt.Sprintf("http://admin:adminpw@localhost:%d", rootPort)
}

func TestGetRootServer(t *testing.T) *Server {
	return TestGetServer(rootPort, rootDir, "", -1, t)
}

func TestGetIntermediateServer(idx int, t *testing.T) *Server {
	return TestGetServer(
		intermediatePort,
		path.Join(intermediateDir, strconv.Itoa(idx)),
		getRootServerURL(),
		-1,
		t)
}

func TestGetServer(port int, home, parentURL string, maxEnroll int, t *testing.T) *Server {
	if home != testdataDir {
		os.RemoveAll(home)
	}
	affiliations := map[string]interface{}{
		"hyperledger": map[string]interface{}{
			"fabric":    []string{"ledger", "orderer", "security"},
			"fabric-ca": nil,
			"sdk":       nil,
		},
		"org2": nil,
	}
	srv := &Server{
		Config: &ServerConfig{
			Port:  port,
			Debug: true,
		},
		CA: CA{
			Config: &CAConfig{
				Intermediate: IntermediateCA{
					ParentServer: ParentServer{
						URL: parentURL,
					},
				},
				Affiliations: affiliations,
				Registry: CAConfigRegistry{
					MaxEnrollments: maxEnroll,
				},
			},
		},
		HomeDir: home,
	}

	err := srv.RegisterBootstrapUser("admin", "adminpw", "")
	if err != nil {
		t.Errorf("Failed to register bootstrap user: %s", err)
		return nil
	}
	return srv
}

func BenchmarkSM2(t *testing.B) {
	t.ReportAllocs()
	for i := 0; i < t.N; i++ {
		priv, err := sm2.GenerateKey()
		if err != nil {
			log.Fatal(err)
		}
		msg := []byte("test")
		sign, err := priv.Sign(rand.Reader, msg, nil)
		if err != nil {
			log.Fatal(err)
		}
		ok := priv.Verify(msg, sign)
		if ok != true {
			fmt.Printf("Verify error\n")
		} else {
			fmt.Printf("Verify ok\n")
		}
	}
}
