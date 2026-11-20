package xraycfg

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// EditDefaults carries the install facts that the runtime config does not
// spell out: whether a managed Nginx front owns the public port and, for TLS,
// the site name used by Nginx.
type EditDefaults struct {
	Mode       string
	PublicPort int
	Domain     string
	// CertFile/KeyFile are the certificate pair the TLS front currently
	// serves, read back from Nginx. They are empty for every non-TLS mode.
	CertFile string
	KeyFile  string
	// LinkFingerprint/LinkSpiderX are stored link preferences (metadata
	// shareLinkOnly). They only shape the share URI; the runtime config never
	// carries them.
	LinkFingerprint string
	LinkSpiderX     string
	// RoutingBlock is the traffic-block state loaded from traffic_blocker.json.
	// Nil keeps the pre-C2 contract: any routing diff is refused.
	RoutingBlock *BlockState
}

// EditRequest carries the operator overrides for `xray config edit`. Zero
// numbers and empty strings keep the current value, which is what makes the
// command a patch instead of a rewrite.
type EditRequest struct {
	Listen           string
	Port             int
	PublicPort       int
	Transport        string
	WSPath           string
	XHTTPPath        string
	GRPCServiceName  string
	Target           string
	ServerNames      []string
	UUID             string
	WSPort           int
	GRPCPort         int
	XHTTPPort        int
	Domain           string
	CertFile         string
	KeyFile          string
	AllowNonLoopback bool
	// Reality credentials. ShortIDSet distinguishes `--short-id ''` (clear the
	// accepted-sid list) from an omitted flag; ShortIDAuto appends a generated
	// id instead of clearing, so the two actions can never be confused.
	ShortIDSet       bool
	ShortID          string
	ShortIDAuto      bool
	ShortIDRemove    string
	LinkFingerprint  string
	LinkFPChanged    bool
	LinkSpiderX      string
	LinkSpiderXSet   bool
	RotatePrivateKey bool
	// Host is the public address clients dial. It is a rendering input, never a
	// config field: Reality keeps its SNI in serverNames, so without it the edit
	// report can only fall back to the SNI, which is not what clients connect to.
	Host string
	// ListShortIDs is read-only: it reports the accepted sids with one link per
	// sid so the operator can hand out the new link before removing the old one.
	ListShortIDs bool
}

// ShortIDLink pairs an accepted shortId with the share link that uses it.
type ShortIDLink struct {
	ShortID  string `json:"shortId"`
	ShareURI string `json:"shareUri"`
}

// EditResult reports what the patch changed and whether the change can drop
// live client sessions.
type EditResult struct {
	Changed    []string
	Mode       string
	Transport  string
	Port       int
	PublicPort int
	Listen     string
	// Target and ServerNames are the effective Reality values after the patch,
	// used by the edit path to probe the origin before saving.
	Target      string
	ServerNames []string
	// Domain/CertFile/KeyFile are the effective TLS values after the patch,
	// used by the edit path to validate the certificate and probe the handshake.
	Domain       string
	CertFile     string
	KeyFile      string
	ShortIDs     []string
	ShortIDLinks []ShortIDLink
	// OldShareURI is the link the clients hold before this patch. A private-key
	// rotation prints it, writes it to the backup directory and uses it to prove
	// that a rollback brought the old credential back.
	OldShareURI string
	// NewShareURI is the link that carries the credential this edit introduced
	// (the appended sid or the rotated key), so verification probes the link the
	// operator is about to hand out, not the first sid.
	NewShareURI            string
	LinkFingerprint        string
	LinkSpiderX            string
	LinkPrefsChanged       bool
	PrivateKeyRotated      bool
	RealityCredentialMoved bool
	Disconnect             bool
	NoChanges              bool
	// Diff lists the changed runtime paths, so --dry-run and the confirmation
	// prompt can show exactly what would move.
	Diff []string
	// BlockPreserved/BlockRuleCount prove that traffic blocking survived the
	// edit. A zero count with BlockPreserved=false means no block was applied.
	BlockPreserved bool
	BlockRuleCount int
}

// EditRuntime applies an EditRequest to an existing runtime config. It reads
// the live values first, regenerates through the same generator as install
// (so the share link and Nginx fragments stay consistent), and then refuses
// the result if anything outside the requested patch changed.
func EditRuntime(raw []byte, base EditDefaults, req EditRequest) (Generated, EditResult, error) {
	root, err := parseRuntime(raw)
	if err != nil {
		return Generated{}, EditResult{}, err
	}
	if base.Mode == ModeTLSDirect {
		// Direct TLS has no Nginx front and no generator spec: a narrow patch
		// keeps the certificate wiring instead of regenerating the config.
		return editDirectTLS(raw, base, req)
	}
	inbounds := asSlice(root["inbounds"])
	spec, sharedUUID, err := editSpecFromRuntime(root, base)
	if err != nil {
		return Generated{}, EditResult{}, err
	}
	if req.UUID != "" {
		if inbound, count, email, ok := multiUserInbound(root); ok {
			// A regeneration would keep clients[0] and silently drop the rest, so
			// point at the one command that rotates a single user across every
			// inbound instead of telling the operator to "use something else".
			return Generated{}, EditResult{}, fmt.Errorf(
				"inbound %d has %d users; 'config edit --uuid' only rewrites the primary and would drop them. Use: idleleo xray user uuid --email %s --new-uuid %s (on the real root add --validator and --service, as with 'xray user add')",
				inbound, count, email, req.UUID)
		}
	}
	if req.UUID != "" && !sharedUUID {
		return Generated{}, EditResult{}, fmt.Errorf(
			"inbounds use different UUIDs; use: idleleo xray user uuid --email <email> --new-uuid %s (it updates every inbound that carries that user)", req.UUID)
	}
	spec.LinkFingerprint, spec.LinkSpiderX = base.LinkFingerprint, base.LinkSpiderX
	shareHost := strings.TrimSpace(req.Host)
	if strings.Contains(shareHost, "/") || strings.Contains(shareHost, "://") {
		return Generated{}, EditResult{}, fmt.Errorf("--host takes the address clients dial (for example 203.0.113.10 or node.example.com), not a URL")
	}
	if shareHost == "" {
		// No dial address was supplied and none is stored, so the report keeps
		// the legacy fallback (the SNI) and the caller warns about it.
		shareHost = shareHostFor(spec)
	}
	reality := spec.Mode == ModeReality || spec.Mode == ModeRealityNginx || spec.Mode == ModeRealityBalance
	oldShare := ""
	if reality {
		// The pre-edit link must carry the same link preferences the clients
		// already hold, otherwise the rollback probe uses a link nobody has.
		if pub, keyErr := DerivePublicKey(spec.PrivateKey); keyErr == nil {
			oldShare = buildShareURI(spec, TransportRaw, shareHost, pub,
				firstShortID(spec.ShortIDs), firstOf(spec.ServerNames, ""))
		}
	}
	if req.ListShortIDs {
		if !reality {
			return Generated{}, EditResult{}, fmt.Errorf("--short-id-list only applies to Reality installs")
		}
		pub, _ := DerivePublicKey(spec.PrivateKey)
		links := make([]ShortIDLink, 0, len(spec.ShortIDs))
		for _, id := range spec.ShortIDs {
			links = append(links, ShortIDLink{ShortID: id, ShareURI: buildShareURI(
				spec, TransportRaw, shareHost, pub, id, firstOf(spec.ServerNames, ""))})
		}
		return Generated{}, EditResult{
			Mode: spec.Mode, Transport: spec.Transport,
			ShortIDs: append([]string{}, spec.ShortIDs...), ShortIDLinks: links,
			NoChanges: true,
		}, nil
	}
	changed, err := applyEditRequest(&spec, base, req)
	if err != nil {
		return Generated{}, EditResult{}, err
	}
	// The running service owns the ports this patch preserves, so a bind probe
	// would report a conflict against our own listener.
	spec.SkipPortProbe = true
	g, err := Generate(spec)
	if err != nil {
		return Generated{}, EditResult{}, err
	}
	// Regeneration starts from a bare generator config. Re-apply the traffic
	// block and hand it the live non-owned rules so an edit never silently
	// drops blocking or the operator's hand-written routing.
	var blockApplied BlockState
	if base.RoutingBlock != nil {
		liveRules, rulesErr := RoutingRulesFromConfig(raw)
		if rulesErr != nil {
			return Generated{}, EditResult{}, rulesErr
		}
		userRules := NonOwnedRules(liveRules, base.RoutingBlock.OwnedRules)
		merged, applied, applyErr := ApplyRoutingBlockWithRules(g.Config, *base.RoutingBlock, userRules)
		if applyErr != nil {
			return Generated{}, EditResult{}, applyErr
		}
		g.Config = merged
		blockApplied = applied
	}
	allow, err := editScopeFor(req, len(inbounds), base.RoutingBlock != nil)
	if err != nil {
		return Generated{}, EditResult{}, err
	}
	diffs, err := diffRuntime(raw, g.Config)
	if err != nil {
		return Generated{}, EditResult{}, err
	}
	for _, d := range diffs {
		if !allow.permits(d) {
			return Generated{}, EditResult{}, fmt.Errorf(
				"refusing to rewrite %q: regeneration would change a field this edit did not ask for; use 'idleleo xray install --rewrite-config'", d)
		}
	}
	linkChanged := hasChange(changed, "link-fingerprint", "link-spiderx")
	// A public-port edit on an Nginx front moves only the generated front and
	// the share link; the Xray inbound keeps its loopback port, so the runtime
	// diff is empty by design. Compare against the live front instead of
	// treating the empty diff as a no-op.
	frontPortChanged := (spec.Mode == ModeRealityNginx || spec.Mode == ModeTLS) &&
		spec.PublicPort > 0 && spec.PublicPort != base.PublicPort
	res := EditResult{
		Changed:           changed,
		Mode:              spec.Mode,
		Transport:         spec.Transport,
		Port:              spec.Port,
		PublicPort:        spec.PublicPort,
		Listen:            spec.Listen,
		Target:            spec.Target,
		ServerNames:       append([]string(nil), spec.ServerNames...),
		Domain:            spec.Domain,
		CertFile:          spec.CertFile,
		KeyFile:           spec.KeyFile,
		ShortIDs:          append([]string{}, spec.ShortIDs...),
		OldShareURI:       oldShare,
		LinkFingerprint:   spec.LinkFingerprint,
		LinkSpiderX:       spec.LinkSpiderX,
		LinkPrefsChanged:  linkChanged,
		PrivateKeyRotated: req.RotatePrivateKey,
		RealityCredentialMoved: hasChange(changed, "reality-private-key", "short-id-add",
			"short-id-auto", "short-id-remove", "short-id-clear"),
		Disconnect: disconnectProne(changed),
		// A link-preference change produces no runtime diff and must still count
		// as a change: the share link the operator copies is the product.
		NoChanges: len(changed) == 0 ||
			(len(diffs) == 0 && !nginxOnlyChange(changed) && !linkChanged && !frontPortChanged),
		Diff:           diffs,
		BlockPreserved: base.RoutingBlock != nil,
		BlockRuleCount: blockApplied.BlockRuleCount(),
	}
	if reality {
		probeSID := firstShortID(spec.ShortIDs)
		if req.ShortIDAuto || (req.ShortIDSet && strings.TrimSpace(req.ShortID) != "") {
			probeSID = lastOf(spec.ShortIDs, probeSID)
		}
		if pub, keyErr := DerivePublicKey(spec.PrivateKey); keyErr == nil {
			res.NewShareURI = buildShareURI(spec, TransportRaw, shareHost, pub,
				probeSID, firstOf(spec.ServerNames, ""))
			g.ShareURI = res.NewShareURI
		}
	}
	return g, res, nil
}

func lastOf(values []string, fallback string) string {
	if len(values) == 0 {
		return fallback
	}
	return values[len(values)-1]
}

func hasChange(changed []string, names ...string) bool {
	for _, c := range changed {
		for _, n := range names {
			if c == n {
				return true
			}
		}
	}
	return false
}

// normalizeXHTTPPath mirrors the Bash installer, which always renders the path
// as "/<path>". A trailing slash is preserved: a real Xray 26.10.31 client
// normalizes it in both directions, so only the leading slash is required.
func normalizeXHTTPPath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return p
	}
	if !strings.HasPrefix(p, "/") {
		return "/" + p
	}
	return p
}

// shareHostFor mirrors the host Generate uses for the share link.
func shareHostFor(spec Spec) string {
	if spec.Domain != "" {
		return spec.Domain
	}
	if len(spec.ServerNames) > 0 {
		return spec.ServerNames[0]
	}
	return spec.Listen
}

// firstShortID is the primary accepted sid for a share link.
func firstShortID(ids []string) string {
	if len(ids) > 0 {
		return ids[0]
	}
	return ""
}

// nginxOnlyChange reports whether the patch only moved front-owned values.
// The TLS domain and certificate paths never appear in the Xray runtime JSON,
// so an empty runtime diff is not a no-op: the Nginx tree still has to be
// rewritten and reloaded.
func nginxOnlyChange(changed []string) bool {
	for _, field := range changed {
		switch field {
		case "domain", "cert-file", "cert-key-file":
			return true
		}
	}
	return false
}

func disconnectProne(changed []string) bool {
	for _, field := range changed {
		switch field {
		case "port", "public-port", "transport", "uuid", "listen",
			"reality-private-key", "short-id-remove", "short-id-clear":
			return true
		}
	}
	return false
}

// editScope limits the regeneration diff to the fields the operator asked
// for. Structural transport/path edits may reshuffle the whole inbound list;
// scalar edits may only touch their own leaf.
type editScope struct {
	structural bool
	exact      map[string]bool
	prefixes   []string
	// block allows the routing/sniffing fields that reapplying the traffic
	// block legitimately rewrites. It is only enabled when a BlockState was
	// supplied, so an install without blocking keeps the strict scope.
	block bool
}

func editScopeFor(req EditRequest, inbounds int, block bool) (editScope, error) {
	a := editScope{exact: map[string]bool{}, block: block}
	if req.Transport != "" || req.WSPath != "" || req.XHTTPPath != "" || req.GRPCServiceName != "" {
		a.structural = true
		// The generated routing rules reference inbound tags, so a transport
		// change legitimately rewrites routing.rules[*].inboundTag.
		a.prefixes = append(a.prefixes, "routing.rules")
		return a, nil
	}
	if req.Port != 0 {
		a.exact["inbounds[0].port"] = true
	}
	if req.Listen != "" {
		for i := 0; i < inbounds; i++ {
			a.exact[fmt.Sprintf("inbounds[%d].listen", i)] = true
		}
	}
	if req.UUID != "" {
		for i := 0; i < inbounds; i++ {
			a.exact[fmt.Sprintf("inbounds[%d].settings.clients[0].id", i)] = true
			// Generate normalises an empty email to the template default, so a
			// UUID edit may also materialise it. Nothing else may change.
			a.exact[fmt.Sprintf("inbounds[%d].settings.clients[0].email", i)] = true
		}
	}
	if req.Target != "" {
		a.prefixes = append(a.prefixes, "inbounds[0].streamSettings.realitySettings.target")
	}
	if len(req.ServerNames) > 0 {
		a.prefixes = append(a.prefixes, "inbounds[0].streamSettings.realitySettings.serverNames")
	}
	if req.ShortIDSet || req.ShortIDAuto || req.ShortIDRemove != "" || req.RotatePrivateKey {
		a.prefixes = append(a.prefixes, "inbounds[0].streamSettings.realitySettings")
	}
	return a, nil
}

func (a editScope) permits(path string) bool {
	if a.block {
		// Reapplying the block rewrites exactly these three surfaces.
		if path == "routing.rules" || path == "routing.domainStrategy" ||
			strings.HasPrefix(path, "routing.rules[") {
			return true
		}
		if strings.Contains(path, ".sniffing") {
			return true
		}
	}
	if a.structural && strings.HasPrefix(path, "inbounds") {
		return true
	}
	if a.exact[path] {
		return true
	}
	for _, p := range a.prefixes {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

// applyEditRequest folds the overrides into the extracted spec and rejects
// combinations that would silently change unrelated topology.
func applyEditRequest(spec *Spec, base EditDefaults, req EditRequest) ([]string, error) {
	changed := []string{}
	nginxFront := base.Mode == ModeRealityNginx || base.Mode == ModeTLS || base.Mode == ModeRealityBalance
	reality := base.Mode == ModeReality || base.Mode == ModeRealityNginx || base.Mode == ModeRealityBalance
	usesWS := spec.Transport == TransportWS || spec.Transport == TransportMulti ||
		(reality && spec.Transport == TransportWS)
	usesXHTTP := spec.Transport == TransportXHTTP || spec.Transport == TransportMulti
	usesGRPC := spec.Transport == TransportGRPC || spec.Transport == TransportMulti
	if req.Transport != "" {
		spec.Transport = req.Transport
		changed = append(changed, "transport")
		usesWS = spec.Transport == TransportWS || spec.Transport == TransportMulti
		usesXHTTP = spec.Transport == TransportXHTTP || spec.Transport == TransportMulti
		usesGRPC = spec.Transport == TransportGRPC || spec.Transport == TransportMulti
	}
	if req.Listen != "" {
		if nginxFront {
			return nil, fmt.Errorf("--listen is owned by Nginx in mode %s; change the proxy or use --rewrite-config", base.Mode)
		}
		spec.Listen = req.Listen
		changed = append(changed, "listen")
	}
	if req.Port != 0 {
		spec.Port = req.Port
		if nginxFront || (base.Mode == ModeReality && base.PublicPort == 0) {
			// Both Nginx-fronted modes treat --port as the public listen port. A
			// direct Reality install has no front, so its listen port is also the
			// port clients dial unless a separate public port was recorded.
			spec.PublicPort = req.Port
		}
		changed = append(changed, "port")
	}
	if req.PublicPort != 0 {
		spec.PublicPort = req.PublicPort
		if base.Mode == ModeRealityNginx {
			spec.Port = req.PublicPort
		}
		changed = append(changed, "public-port")
	}
	if req.WSPath != "" {
		if !usesWS {
			return nil, fmt.Errorf("--ws-path requires a transport with ws")
		}
		if req.XHTTPPath != "" {
			return nil, fmt.Errorf("specify only one of --ws-path and --xhttp-path")
		}
		spec.Path = req.WSPath
		changed = append(changed, "ws-path")
	}
	if req.XHTTPPath != "" {
		if !usesXHTTP {
			return nil, fmt.Errorf("--xhttp-path requires a transport with xhttp")
		}
		if spec.Transport == TransportMulti {
			return nil, fmt.Errorf("the multi transport fixes the xhttp path; use a single xhttp transport to change it")
		}
		spec.Path = normalizeXHTTPPath(req.XHTTPPath)
		changed = append(changed, "xhttp-path")
	}
	if req.GRPCServiceName != "" {
		if !usesGRPC {
			return nil, fmt.Errorf("--grpc-service-name requires a transport with grpc")
		}
		spec.ServiceName = req.GRPCServiceName
		changed = append(changed, "grpc-service-name")
	}
	if req.Target != "" {
		if !reality {
			return nil, fmt.Errorf("--target only applies to Reality modes")
		}
		spec.Target = req.Target
		changed = append(changed, "target")
	}
	if len(req.ServerNames) > 0 {
		if !reality {
			return nil, fmt.Errorf("--server-names only applies to Reality modes")
		}
		spec.ServerNames = req.ServerNames
		changed = append(changed, "server-names")
	}
	if req.UUID != "" {
		spec.UUID = req.UUID
		changed = append(changed, "uuid")
	}
	if req.WSPort != 0 {
		if !usesWS {
			return nil, fmt.Errorf("--ws-port requires a transport with ws")
		}
		spec.WSPort = req.WSPort
		changed = append(changed, "ws-port")
	}
	if req.GRPCPort != 0 {
		if !usesGRPC {
			return nil, fmt.Errorf("--grpc-port requires a transport with grpc")
		}
		spec.GRPCPort = req.GRPCPort
		changed = append(changed, "grpc-port")
	}
	if req.XHTTPPort != 0 {
		if !usesXHTTP {
			return nil, fmt.Errorf("--xhttp-port requires a transport with xhttp")
		}
		spec.XHTTPPort = req.XHTTPPort
		changed = append(changed, "xhttp-port")
	}
	if req.AllowNonLoopback {
		spec.AllowNonLoopback = true
	}
	if req.Domain != "" {
		if base.Mode != ModeTLS {
			return nil, fmt.Errorf("--domain only applies to TLS installs; use --server-names for Reality")
		}
		if req.Domain != spec.Domain {
			spec.Domain = req.Domain
			changed = append(changed, "domain")
		}
	}
	if req.CertFile != "" {
		if base.Mode != ModeTLS {
			return nil, fmt.Errorf("--cert only applies to TLS installs; Reality has no certificate")
		}
		if req.CertFile != spec.CertFile {
			spec.CertFile = req.CertFile
			changed = append(changed, "cert-file")
		}
	}
	if req.KeyFile != "" {
		if base.Mode != ModeTLS {
			return nil, fmt.Errorf("--cert-key only applies to TLS installs; Reality has no certificate")
		}
		if req.KeyFile != spec.KeyFile {
			spec.KeyFile = req.KeyFile
			changed = append(changed, "cert-key-file")
		}
	}
	credential := req.ShortIDSet || req.ShortIDAuto || req.ShortIDRemove != "" || req.RotatePrivateKey
	if credential && !reality {
		return nil, fmt.Errorf("Reality credential flags only apply to Reality installs")
	}
	if req.ShortIDSet && req.ShortIDAuto {
		return nil, fmt.Errorf("--short-id and --short-id-auto are separate actions; pick one")
	}
	if req.ShortIDRemove != "" && (req.ShortIDSet || req.ShortIDAuto) {
		return nil, fmt.Errorf("--short-id-remove cannot be combined with --short-id/--short-id-auto")
	}
	if credential {
		if spec.ShortIDs == nil {
			spec.ShortIDs = []string{}
		}
		switch {
		case req.ShortIDAuto:
			// Append without removing: existing clients keep their sid while the
			// operator hands out the new link.
			id, err := NewShortID()
			if err != nil {
				return nil, err
			}
			spec.ShortIDs = appendUnique(spec.ShortIDs, id)
			changed = append(changed, "short-id-auto")
		case req.ShortIDSet && req.ShortID == "":
			// Explicit clear, never inferred from an empty value elsewhere.
			if len(spec.ShortIDs) > 0 {
				spec.ShortIDs = []string{}
				changed = append(changed, "short-id-clear")
			}
		case req.ShortIDSet:
			id := strings.TrimSpace(req.ShortID)
			if !validShortID(id) {
				return nil, fmt.Errorf("--short-id must be 1-16 hex characters with even length, or empty to clear all")
			}
			if !containsString(spec.ShortIDs, id) {
				spec.ShortIDs = appendUnique(spec.ShortIDs, id)
				changed = append(changed, "short-id-add")
			}
		case req.ShortIDRemove != "":
			id := strings.TrimSpace(req.ShortIDRemove)
			if !containsString(spec.ShortIDs, id) {
				return nil, fmt.Errorf("shortId %q is not in the accepted list", id)
			}
			spec.ShortIDs = removeString(spec.ShortIDs, id)
			changed = append(changed, "short-id-remove")
		}
		if req.RotatePrivateKey {
			private, _, err := NewRealityKeys()
			if err != nil {
				return nil, err
			}
			spec.PrivateKey = private
			changed = append(changed, "reality-private-key")
		}
	}
	if req.LinkFPChanged {
		fp := strings.TrimSpace(req.LinkFingerprint)
		if fp != "" && !validFingerprint(fp) {
			return nil, fmt.Errorf("--fp must be one of chrome, firefox, safari, ios, android, edge, 360, qq, random")
		}
		spec.LinkFingerprint = fp
		changed = append(changed, "link-fingerprint")
	}
	if req.LinkSpiderXSet {
		spx := strings.TrimSpace(req.LinkSpiderX)
		if spx != "" && !strings.HasPrefix(spx, "/") {
			return nil, fmt.Errorf("--spx must start with '/' (it is the spider path in the share link)")
		}
		spec.LinkSpiderX = spx
		changed = append(changed, "link-spiderx")
	}
	return changed, nil
}

// validFingerprint keeps the share link to uTLS profiles Xray clients know.
func validFingerprint(fp string) bool {
	switch strings.ToLower(fp) {
	case "chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized":
		return true
	}
	return false
}

func containsString(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

func appendUnique(values []string, v string) []string {
	if containsString(values, v) {
		return values
	}
	return append(values, v)
}

func removeString(values []string, drop string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		if v != drop {
			out = append(out, v)
		}
	}
	return out
}

// editSpecFromRuntime extracts the values Generate needs from a live config.
// It returns sharedUUID=false when the inbounds disagree on the client id,
// because a single regeneration would then rewrite every user.
func editSpecFromRuntime(root map[string]any, base EditDefaults) (Spec, bool, error) {
	inbounds := asSlice(root["inbounds"])
	if len(inbounds) == 0 {
		return Spec{}, false, fmt.Errorf("runtime config has no inbounds")
	}
	first := asMap(inbounds[0])
	spec := Spec{
		Mode:        base.Mode,
		Port:        asInt(first["port"]),
		Listen:      asString(first["listen"]),
		PublicPort:  base.PublicPort,
		Domain:      base.Domain,
		CertFile:    base.CertFile,
		KeyFile:     base.KeyFile,
		Path:        defaultPath,
		ServiceName: defaultGRPCService,
	}
	if base.Mode == ModeTLS {
		// TLS keeps Xray on a pool port; the public port lives in Nginx. When
		// the front predates CertFile parsing, fall back to the generator
		// default so the comparison stays honest.
		spec.Port = base.PublicPort
		if spec.CertFile == "" {
			spec.CertFile = DefaultCertFile
		}
		if spec.KeyFile == "" {
			spec.KeyFile = DefaultKeyFile
		}
	}
	networks := make([]string, 0, len(inbounds))
	var uuid, email, flow, wsPath, xhttpPath string
	sharedUUID := true
	for i, item := range inbounds {
		inbound := asMap(item)
		stream := asMap(inbound["streamSettings"])
		network := asString(stream["network"])
		if network == "" {
			network = TransportRaw
		}
		networks = append(networks, network)
		switch network {
		case TransportWS:
			if p := asString(asMap(stream["wsSettings"])["path"]); p != "" {
				wsPath = p
			}
			if i > 0 || spec.Mode == ModeTLS {
				// TLS keeps its primary ws inbound on a pool port.
				spec.WSPort = asInt(inbound["port"])
			}
		case TransportGRPC:
			if s := asString(asMap(stream["grpcSettings"])["serviceName"]); s != "" {
				spec.ServiceName = s
			}
			if i > 0 || spec.Mode == ModeTLS || spec.Mode == ModeNone {
				spec.GRPCPort = asInt(inbound["port"])
			}
		case TransportXHTTP:
			if p := asString(asMap(stream["xhttpSettings"])["path"]); p != "" {
				xhttpPath = p
			}
			if i > 0 || spec.Mode == ModeTLS || spec.Mode == ModeNone {
				spec.XHTTPPort = asInt(inbound["port"])
			}
		}
		clients := asSlice(asMap(inbound["settings"])["clients"])
		if len(clients) > 0 {
			c := asMap(clients[0])
			id := asString(c["id"])
			if i == 0 {
				uuid, email, flow = id, asString(c["email"]), asString(c["flow"])
			} else if id != uuid {
				sharedUUID = false
			}
		}
	}
	var err error
	spec.Transport, err = transportFromNetworks(spec.Mode, networks)
	if err != nil {
		return Spec{}, false, err
	}
	if wsPath != "" {
		spec.Path = wsPath
	} else if xhttpPath != "" && spec.Transport != TransportMulti {
		spec.Path = xhttpPath
	}
	spec.UUID = uuid
	spec.Email = email
	spec.Flow = flow
	firstStream := asMap(first["streamSettings"])
	switch asString(firstStream["security"]) {
	case "reality":
		rs := asMap(firstStream["realitySettings"])
		spec.Target = asString(rs["target"])
		if spec.Target == "" {
			spec.Target = asString(rs["dest"])
		}
		spec.PrivateKey = asString(rs["privateKey"])
		spec.ShortIDs = []string{}
		for _, id := range asSlice(rs["shortIds"]) {
			spec.ShortIDs = append(spec.ShortIDs, asString(id))
		}
		if len(spec.ShortIDs) > 0 {
			spec.ShortID = spec.ShortIDs[0]
		}
		for _, sn := range asSlice(rs["serverNames"]) {
			spec.ServerNames = append(spec.ServerNames, asString(sn))
		}
	case "tls":
		// Direct TLS (no managed front) is not one of the supported install
		// modes; regenerating it would change the certificate wiring.
		return Spec{}, false, fmt.Errorf("direct TLS configs are not editable; reinstall with --mode tls")
	}
	if base.Mode == ModeRealityNginx || base.Mode == ModeRealityBalance || base.Mode == ModeTLS {
		// These modes keep Xray on the loopback backend port and put the
		// operator-facing port on the front; spec.Port is the front port.
		spec.Port = base.PublicPort
	}
	// A direct Reality install has no front to report the public port, so the
	// link must fall back to the port the inbound actually listens on.
	if base.Mode == ModeReality && spec.PublicPort == 0 {
		spec.PublicPort = spec.Port
	}
	if spec.Mode == ModeRealityBalance {
		// The editable config is always the primary: it owns the Reality inbound
		// and the Nginx front. Backend upstream files are never regenerated by an
		// edit; deploy compares their content hash before and after.
		spec.BalanceRole = BalanceRolePrimary
	}
	spec.LinkFingerprint, spec.LinkSpiderX = base.LinkFingerprint, base.LinkSpiderX
	return spec, sharedUUID, nil
}

// multiUserInbound reports the first inbound that carries more than one VLESS
// client. Such a config cannot be regenerated from a single UUID: the generator
// emits exactly one client per inbound, so the extra users would disappear.
func multiUserInbound(root map[string]any) (int, int, string, bool) {
	for i, item := range asSlice(root["inbounds"]) {
		inbound := asMap(item)
		clients := asSlice(asMap(inbound["settings"])["clients"])
		if len(clients) > 1 {
			return i, len(clients), asString(asMap(clients[0])["email"]), true
		}
	}
	return 0, 0, "", false
}

// transportFromNetworks maps the inbound network list back to the transport
// value used by the wizard and the generator.
func transportFromNetworks(mode string, networks []string) (string, error) {
	seen := make([]string, 0, len(networks))
	for _, n := range networks {
		found := false
		for _, s := range seen {
			if s == n {
				found = true
			}
		}
		if !found {
			seen = append(seen, n)
		}
	}
	reality := mode == ModeReality || mode == ModeRealityNginx
	others := seen
	if reality {
		others = nil
		for _, n := range seen {
			if n != TransportRaw {
				others = append(others, n)
			}
		}
		if len(others) == 0 {
			return TransportRaw, nil
		}
	}
	switch len(others) {
	case 1:
		return others[0], nil
	case 3:
		return TransportMulti, nil
	default:
		return "", fmt.Errorf("unsupported inbound network combination %v", seen)
	}
}

func parseRuntime(raw []byte) (map[string]any, error) {
	var root map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&root); err != nil {
		return nil, fmt.Errorf("runtime config is not valid JSON: %w", err)
	}
	if root == nil {
		return nil, fmt.Errorf("runtime config must be a JSON object")
	}
	return root, nil
}

// diffRuntime lists every leaf that differs between two configs, using paths
// such as inbounds[0].port so the allowance check can decide precisely.
func diffRuntime(oldRaw, newRaw []byte) ([]string, error) {
	oldRoot, err := parseRuntime(oldRaw)
	if err != nil {
		return nil, err
	}
	newRoot, err := parseRuntime(newRaw)
	if err != nil {
		return nil, err
	}
	var out []string
	diffValue("", oldRoot, newRoot, &out)
	sort.Strings(out)
	return out, nil
}

func diffValue(path string, a, b any, out *[]string) {
	am, aOK := a.(map[string]any)
	bm, bOK := b.(map[string]any)
	if aOK && bOK {
		keys := map[string]bool{}
		for k := range am {
			keys[k] = true
		}
		for k := range bm {
			keys[k] = true
		}
		names := make([]string, 0, len(keys))
		for k := range keys {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, k := range names {
			diffValue(joinPath(path, k), am[k], bm[k], out)
		}
		return
	}
	as, aOK := a.([]any)
	bs, bOK := b.([]any)
	if aOK && bOK {
		if len(as) != len(bs) {
			*out = append(*out, path)
			return
		}
		for i := range as {
			diffValue(fmt.Sprintf("%s[%d]", path, i), as[i], bs[i], out)
		}
		return
	}
	if !scalarEqual(a, b) {
		*out = append(*out, path)
	}
}

func joinPath(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

func scalarEqual(a, b any) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	an, aNum := a.(json.Number)
	bn, bNum := b.(json.Number)
	if aNum && bNum {
		return an.String() == bn.String()
	}
	return fmt.Sprintf("%v", a) == fmt.Sprintf("%v", b)
}

func asMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	if m == nil {
		return map[string]any{}
	}
	return m
}

func asSlice(v any) []any {
	s, _ := v.([]any)
	return s
}

func asString(v any) string {
	s, _ := v.(string)
	return s
}

func asInt(v any) int {
	switch t := v.(type) {
	case json.Number:
		i, _ := t.Int64()
		return int(i)
	case float64:
		return int(t)
	case int:
		return t
	default:
		return 0
	}
}
