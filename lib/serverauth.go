/*
Copyright IBM Corp. 2016 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

                 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package lib

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/cloudflare/cfssl/api"
	cerr "github.com/cloudflare/cfssl/errors"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/revoke"
	"github.com/tjfoc/fabric-ca-gm/util"
)

const (
	enrollmentIDHdrName = "__eid__"
	caHdrName           = "__caname__"
)

// AuthType is the enum for authentication types: basic and token
type authType int

const (
	noAuth authType = iota
	basic           // basic = 1
	token           // token = 2
	super           // super = 3
)

// Fabric CA authentication handler
type fcaAuthHandler struct {
	server   *Server
	authType authType
	next     http.Handler
}

type caname struct {
	CAName string
}

var authError = cerr.NewBadRequest(errors.New("Authorization failure"))

func (ah *fcaAuthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	err := ah.serveHTTP(w, r)
	if err != nil {
		api.HandleError(w, err)
	} else {
		ah.next.ServeHTTP(w, r)
	}
}

// Handle performs authentication
func (ah *fcaAuthHandler) serveHTTP(w http.ResponseWriter, r *http.Request) error {
	log.Debugf("Received request\n%s", util.HTTPRequestToString(r))
	// read body
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Debugf("Failed to read body: %s", err)
		return cerr.NewBadRequest(errors.New("Authorization failure1"))
	}
	r.Body = ioutil.NopCloser(bytes.NewReader(body))

	var req caname

	if len(body) != 0 {
		err = json.Unmarshal(body, &req)
		if err != nil {
			return err
		}
	}

	if req.CAName == "" {
		log.Debugf("Directing traffic to default CA")
		req.CAName = ah.server.CA.Config.CA.Name
	} else {
		log.Debugf("Directing traffic to CA %s", req.CAName)
	}

	// Look up CA to see if CA exist by that name
	if _, ok := ah.server.caMap[req.CAName]; !ok {

		return fmt.Errorf("CA '%s' does not exist", req.CAName)
	}

	r.Header.Set(caHdrName, req.CAName)

	authHdr := r.Header.Get("authorization")
	switch ah.authType {
	case noAuth:
		return nil
	case super:
		log.Infof("authtype=%+v", ah.authType)
		// No authentication required
		return nil
	case basic:
		if authHdr == "" {
			log.Debug("No authorization header")
			return cerr.NewBadRequest(errors.New("Authorization failure2"))
		}
		user, pwd, ok := r.BasicAuth()
		if ok {
			if ah.authType != basic {
				log.Debugf("Basic auth is not allowed; found %s", authHdr)
				return errBasicAuthNotAllowed
			}
			u, err := ah.server.caMap[req.CAName].registry.GetUser(user, nil)
			if err != nil {
				log.Debugf("Failed to get identity '%s': %s", user, err)
				log.Infof("Failed to get identity '%s': %s", user, err)
				return cerr.NewBadRequest(errors.New("Authorization failure3"))
			}
			caMaxEnrollments := ah.server.caMap[req.CAName].Config.Registry.MaxEnrollments
			if caMaxEnrollments == 0 {
				msg := fmt.Sprintf("Enrollments are disabled; user '%s' cannot enroll", user)
				log.Debugf(msg)
				return errors.New(msg)
			}
			err = u.Login(pwd, caMaxEnrollments)
			if err != nil {
				log.Debugf("Failed to login '%s': %s", user, err)
				return cerr.NewBadRequest(errors.New("Authorization failure4"))
			}
			log.Debug("Identity/Pass was correct")
			r.Header.Set(enrollmentIDHdrName, user)
			return nil
		}
		return cerr.NewBadRequest(errors.New("Authorization failure5"))
	case token:
		ca := ah.server.caMap[req.CAName]
		//log.Infof("????????????????????????? caname = %s", req.CAName)
		// verify token
		cert, err2 := util.VerifyToken(ca.csp, authHdr, body)
		if err2 != nil {
			log.Debugf("Failed to verify token: %s", err2)
			return cerr.NewBadRequest(errors.New("Authorization failure6"))
		}

		id := util.GetEnrollmentIDFromX509Certificate(cert)
		log.Debugf("Checking for revocation/expiration of certificate owned by '%s'", id)
		// VerifyCertificate ensures that the certificate passed in hasn't
		// expired and checks the CRL for the server.
		revokedOrExpired, checked := revoke.VerifyCertificate(cert)
		if revokedOrExpired {
			log.Debugf("Certificate owned by '%s' has expired", id)
			return cerr.NewBadRequest(errors.New("Authorization failure7"))
		}

		if !checked {
			log.Debug("A failure occurred while checking for revocation and expiration")
			return cerr.NewBadRequest(errors.New("Authorization failure8"))
		}

		// Make sure the caller's cert was issued by this CA
		err2 = ca.VerifyCertificate(cert)
		if err2 != nil {
			log.Debugf("Failed to verify certificate: %s", err2)
			return cerr.NewBadRequest(errors.New("Authorization failure9"))
		}

		aki := hex.EncodeToString(cert.AuthorityKeyId)
		serial := util.GetSerialAsHex(cert.SerialNumber)
		//aki := cert.AuthorityKeyId.String()
		//serial := cert.SerialNumber.String()
		aki = strings.ToLower(strings.TrimLeft(aki, "0"))
		serial = strings.ToLower(strings.TrimLeft(serial, "0"))

		certs, err := ca.CertDBAccessor().GetCertificate(serial, aki)
		if err != nil {
			return cerr.NewBadRequest(errors.New("Authorization failure10"))
		}

		if len(certs) == 0 {
			log.Error("No certificates found for provided serial and aki")
			return cerr.NewBadRequest(errors.New("Authorization failure11"))
		}

		for _, certificate := range certs {
			if certificate.Status == "revoked" {
				return cerr.NewBadRequest(errors.New("Authorization failure12"))
			}
		}
		log.Debugf("Successful authentication of '%s'", id)
		r.Header.Set(enrollmentIDHdrName, util.GetEnrollmentIDFromX509Certificate(cert))

		return nil

	default: // control should never reach here
		log.Errorf("No handler for the authentication type: %d", ah.authType)
		return cerr.NewBadRequest(errors.New("Authorization failure13"))
	}
	return nil
}
