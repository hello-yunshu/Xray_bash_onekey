package xraycfg

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
)

// DirectTLSPatch is the result of a narrow patch against a config whose
// inbounds terminate TLS themselves (no managed Nginx front). Only the
// certificate pair, an existing serverName and — for a single inbound — the
// listener may move; everything else is asserted byte-for-byte.
type DirectTLSPatch struct {
	Config   []byte
	Changed  []string
	Domain   string
	Listen   string
	Port     int
	CertFile string
	KeyFile  string
}

// PatchDirectTLS applies `xray config edit` overrides to a direct TLS config.
func PatchDirectTLS(raw []byte, req EditRequest) (DirectTLSPatch, error) {
	if err := rejectNonDirectTLSFields(req); err != nil {
		return DirectTLSPatch{}, err
	}
	if (req.CertFile == "") != (req.KeyFile == "") {
		return DirectTLSPatch{}, fmt.Errorf("direct TLS edits need both --cert and --cert-key")
	}
	if req.Port < 0 || req.Port > 65535 {
		return DirectTLSPatch{}, fmt.Errorf("port %d is outside 1-65535", req.Port)
	}
	root, err := parseRuntime(raw)
	if err != nil {
		return DirectTLSPatch{}, err
	}
	original, err := parseRuntime(raw)
	if err != nil {
		return DirectTLSPatch{}, err
	}
	inbounds := asSlice(root["inbounds"])
	if len(inbounds) == 0 {
		return DirectTLSPatch{}, fmt.Errorf("runtime config has no inbounds")
	}
	var tlsIdx []int
	for i, item := range inbounds {
		stream := asMap(asMap(item)["streamSettings"])
		if asString(stream["security"]) != "tls" {
			continue
		}
		tls := asMap(stream["tlsSettings"])
		certs := asSlice(tls["certificates"])
		if len(certs) == 0 {
			return DirectTLSPatch{}, fmt.Errorf("inbound %d has no tlsSettings.certificates[0]", i)
		}
		cert := asMap(certs[0])
		if asString(cert["certificateFile"]) == "" || asString(cert["keyFile"]) == "" {
			return DirectTLSPatch{}, fmt.Errorf("inbound %d is missing certificateFile/keyFile", i)
		}
		tlsIdx = append(tlsIdx, i)
	}
	if len(tlsIdx) == 0 {
		return DirectTLSPatch{}, fmt.Errorf("config has no direct TLS inbound to edit")
	}
	if (req.Listen != "" || req.Port != 0) && len(tlsIdx) > 1 {
		return DirectTLSPatch{}, fmt.Errorf(
			"direct TLS has %d TLS inbounds; --listen/--port need exactly one (edit the config file to move several)",
			len(tlsIdx))
	}
	firstIdx := tlsIdx[0]
	firstStream := asMap(asMap(inbounds[firstIdx])["streamSettings"])
	firstTLS := asMap(firstStream["tlsSettings"])
	firstCert := asMap(asSlice(firstTLS["certificates"])[0])
	oldCert := asString(firstCert["certificateFile"])
	oldKey := asString(firstCert["keyFile"])
	oldListen := asString(asMap(inbounds[firstIdx])["listen"])
	oldPort := asInt(asMap(inbounds[firstIdx])["port"])
	oldDomain := asString(firstTLS["serverName"])

	changed := make([]string, 0, 5)
	for _, i := range tlsIdx {
		stream := asMap(asMap(inbounds[i])["streamSettings"])
		tls := asMap(stream["tlsSettings"])
		cert := asMap(asSlice(tls["certificates"])[0])
		if req.CertFile != "" {
			cert["certificateFile"] = req.CertFile
			cert["keyFile"] = req.KeyFile
		}
		if req.Domain != "" {
			if _, ok := tls["serverName"]; ok {
				tls["serverName"] = req.Domain
			}
		}
	}
	if req.Listen != "" {
		asMap(inbounds[firstIdx])["listen"] = req.Listen
	}
	if req.Port != 0 {
		asMap(inbounds[firstIdx])["port"] = json.Number(strconv.Itoa(req.Port))
	}
	if req.CertFile != "" && req.CertFile != oldCert {
		changed = append(changed, "cert-file")
	}
	if req.KeyFile != "" && req.KeyFile != oldKey {
		changed = append(changed, "cert-key-file")
	}
	if req.Domain != "" && req.Domain != oldDomain && oldDomain != "" {
		changed = append(changed, "domain")
	}
	if req.Listen != "" && req.Listen != oldListen {
		changed = append(changed, "listen")
	}
	if req.Port != 0 && req.Port != oldPort {
		changed = append(changed, "port")
	}
	patched, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return DirectTLSPatch{}, err
	}
	patched = append(patched, '\n')
	if err := assertDirectTLSOnlyChanged(original, root, tlsIdx, firstIdx, req, oldCert, oldKey, oldDomain, oldListen, oldPort); err != nil {
		return DirectTLSPatch{}, err
	}
	domain := oldDomain
	if req.Domain != "" {
		domain = req.Domain
	}
	listen := oldListen
	if req.Listen != "" {
		listen = req.Listen
	}
	port := oldPort
	if req.Port != 0 {
		port = req.Port
	}
	certFile, keyFile := oldCert, oldKey
	if req.CertFile != "" {
		certFile, keyFile = req.CertFile, req.KeyFile
	}
	return DirectTLSPatch{
		Config: patched, Changed: changed, Domain: domain,
		Listen: listen, Port: port, CertFile: certFile, KeyFile: keyFile,
	}, nil
}

func rejectNonDirectTLSFields(req EditRequest) error {
	unsupported := req.PublicPort != 0 || req.Transport != "" || req.WSPath != "" ||
		req.XHTTPPath != "" || req.GRPCServiceName != "" || req.Target != "" ||
		len(req.ServerNames) > 0 || req.UUID != "" || req.WSPort != 0 ||
		req.GRPCPort != 0 || req.XHTTPPort != 0 || req.AllowNonLoopback ||
		req.ShortIDSet || req.ShortID != "" || req.ShortIDAuto ||
		req.ShortIDRemove != "" || req.LinkFingerprint != "" || req.LinkFPChanged ||
		req.LinkSpiderX != "" || req.LinkSpiderXSet || req.RotatePrivateKey ||
		req.ListShortIDs
	if !unsupported {
		return nil
	}
	return fmt.Errorf("direct TLS supports only --domain/--cert/--cert-key/--listen/--port")
}

// editDirectTLS turns a narrow patch into the EditResult the deploy layer
// consumes. Unlike the generated modes there is no spec to rebuild, so the
// share link is best-effort and a failure never blocks the edit.
func editDirectTLS(raw []byte, base EditDefaults, req EditRequest) (Generated, EditResult, error) {
	patch, err := PatchDirectTLS(raw, req)
	if err != nil {
		return Generated{}, EditResult{}, err
	}
	root, err := parseRuntime(patch.Config)
	if err != nil {
		return Generated{}, EditResult{}, err
	}
	transport := TransportRaw
	if inbounds := asSlice(root["inbounds"]); len(inbounds) > 0 {
		if network := asString(asMap(asMap(inbounds[0])["streamSettings"])["network"]); network != "" {
			transport = network
		}
	}
	host := patch.Domain
	if host == "" {
		host = base.Domain
	}
	g := Generated{
		Mode: ModeTLSDirect, Transport: transport, Port: patch.Port,
		Listen: patch.Listen, Config: patch.Config,
	}
	if info, shareErr := ShareConfig(patch.Config, ShareOptions{
		Host: host, PublicPort: patch.Port, PublicSecurity: "tls",
		Fingerprint: base.LinkFingerprint, SpiderX: base.LinkSpiderX,
	}); shareErr == nil {
		g.ShareURI = info.ShareURI
	}
	diffs, err := diffRuntime(raw, patch.Config)
	if err != nil {
		return Generated{}, EditResult{}, err
	}
	return g, EditResult{
		Changed: patch.Changed, Mode: ModeTLSDirect, Transport: transport,
		Port: patch.Port, PublicPort: patch.Port, Listen: patch.Listen,
		Domain: patch.Domain, CertFile: patch.CertFile, KeyFile: patch.KeyFile,
		Disconnect: len(patch.Changed) > 0, NoChanges: len(patch.Changed) == 0,
		Diff: diffs, LinkFingerprint: base.LinkFingerprint, LinkSpiderX: base.LinkSpiderX,
	}, nil
}

// assertDirectTLSOnlyChanged restores every allowed leaf on a copy and
// requires the result to equal the original object. Any other difference means
// the patch reached somewhere it must not touch.
func assertDirectTLSOnlyChanged(original, patched map[string]any, tlsIdx []int, firstIdx int, req EditRequest, oldCert, oldKey, oldDomain, oldListen string, oldPort int) error {
	guardRaw, err := json.Marshal(patched)
	if err != nil {
		return err
	}
	guard, err := parseRuntime(guardRaw)
	if err != nil {
		return err
	}
	inbounds := asSlice(guard["inbounds"])
	for _, i := range tlsIdx {
		tls := asMap(asMap(asMap(inbounds[i])["streamSettings"])["tlsSettings"])
		cert := asMap(asSlice(tls["certificates"])[0])
		cert["certificateFile"] = oldCert
		cert["keyFile"] = oldKey
		if req.Domain != "" && oldDomain != "" {
			tls["serverName"] = oldDomain
		}
	}
	if req.Listen != "" {
		asMap(inbounds[firstIdx])["listen"] = oldListen
	}
	if req.Port != 0 {
		asMap(inbounds[firstIdx])["port"] = json.Number(strconv.Itoa(oldPort))
	}
	if !reflect.DeepEqual(original, guard) {
		return fmt.Errorf("refusing to rewrite fields this direct TLS edit did not request")
	}
	return nil
}
