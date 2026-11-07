package demo

type Service struct {
	Name string `json:"name"`
	UID  uint32 `json:"uid"`
	GID  uint32 `json:"gid"`
}
type Dispatcher struct {
	Name       string `json:"name"`
	UID        uint32 `json:"uid"`
	GID        uint32 `json:"gid"`
	Principal  string `json:"principal"`
	Generation string `json:"generation"`
}
type Executor struct {
	ID     string `json:"id"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}
type Runtime struct {
	Admitted                   bool `json:"admitted"`
	InventoryQualified         bool `json:"inventory_qualified"`
	CreationExclusionQualified bool `json:"creation_exclusion_qualified"`
	InterpreterQualified       bool `json:"interpreter_qualified"`
}
type Row struct {
	Name             string `json:"name"`
	UID              uint32 `json:"uid"`
	GID              uint32 `json:"gid"`
	Generation       string `json:"generation"`
	OwningDispatcher string `json:"owning_dispatcher"`
	Home             string `json:"home"`
	Workspace        string `json:"workspace"`
	CopyDigest       string `json:"copy_digest"`
}
type Roster struct {
	Format         string     `json:"format"`
	SourceRevision string     `json:"source_revision"`
	BootID         string     `json:"boot_id"`
	Operator       Service    `json:"operator"`
	Dispatcher     Dispatcher `json:"dispatcher"`
	Executor       Executor   `json:"executor"`
	Runtime        Runtime    `json:"runtime"`
	Accounts       []Row      `json:"accounts"`
}

// FixedExecutorApproved restricts Codex leasing and execution to the Codex row.
// The canonical P1 schema also permits a witness row, which grants no Codex use.
func FixedExecutorApproved(r Roster) bool {
	return r.Executor.ID == ExecutorID && r.Executor.Path == ExecutorPath && hash.MatchString(r.Executor.SHA256)
}

// DecodeRoster accepts the closed PR75 schema: one executor row selected from
// the two exact ID/path pairs. No additional executor or alternate schema is
// admitted. The source revision is pinned independently of these path checks.
func DecodeRoster(raw []byte) (Roster, error) {
	var r Roster
	if len(raw) > 128*1024 || decodeClosed(raw, &r) != nil || r.Format != "swarma-user-manager demo-roster/1" || r.SourceRevision != FrozenCopySourceRevision || !boot.MatchString(r.BootID) || r.Operator != (Service{"agent", 1001, 1001}) {
		return Roster{}, ErrRefused
	}
	d := r.Dispatcher
	if d.Name != "swarma-demo-dispatcher" || d.Principal != d.Name || d.UID != 1101 || d.GID != 1101 || !Generation(d.Generation) {
		return Roster{}, ErrRefused
	}
	witness := r.Executor.ID == "swarma-demo-executor" && r.Executor.Path == "/usr/local/libexec/swarma/swarma-demo-executor"
	codex := r.Executor.ID == ExecutorID && r.Executor.Path == ExecutorPath
	if (!witness && !codex) || !hash.MatchString(r.Executor.SHA256) || len(r.Accounts) != 3 {
		return Roster{}, ErrRefused
	}
	names := map[string]bool{}
	ids := map[uint32]bool{}
	gens := map[string]bool{d.Generation: true}
	for _, a := range r.Accounts {
		if (a.Name != "swarma-demo-01" && a.Name != "swarma-demo-02" && a.Name != "swarma-demo-03") || names[a.Name] || a.UID < 30000 || a.UID > 30019 || a.GID != a.UID || ids[a.UID] || !Generation(a.Generation) || gens[a.Generation] || a.OwningDispatcher != d.Principal || a.Home != "/srv/swarma-demo/home/"+a.Name || a.Workspace != "/srv/swarma-demo/work/"+a.Name || !hash.MatchString(a.CopyDigest) {
			return Roster{}, ErrRefused
		}
		names[a.Name] = true
		ids[a.UID] = true
		gens[a.Generation] = true
	}
	return r, nil
}
func ReadRoster(path string) (Roster, error) {
	if path != RosterPath {
		return Roster{}, ErrRefused
	}
	b, e := readRoot(path, 0644, 128*1024)
	if e != nil {
		return Roster{}, e
	}
	return DecodeRoster(b)
}
func (r Roster) Principal(uid uint32, launch LaunchRecord) (Row, error) {
	if r.BootID != launch.BootID || launch.UID != uid || !r.Runtime.Admitted || !r.Runtime.InventoryQualified || !r.Runtime.CreationExclusionQualified || !r.Runtime.InterpreterQualified {
		return Row{}, ErrRefused
	}
	for _, a := range r.Accounts {
		if a.UID == uid && a.Generation == launch.Generation && a.OwningDispatcher == r.Dispatcher.Principal && r.Dispatcher.UID == 1101 {
			return a, nil
		}
	}
	return Row{}, ErrRefused
}
