//go:build linux && amd64

package qualify

import (
 "bytes"
 "context"
 "os"
 "path/filepath"
 "testing"

 "github.com/relux-works/swarma-credential-broker/internal/qualification"
 "github.com/relux-works/swarma-credential-broker/internal/wire"
)

// Claim: a helper that stops before launch, or a missing launcher, must not
// acquire canonical case execution credit. Both fixtures use only local state.
func TestReviewPeerStartupEvidence(t *testing.T) {
 configured:=configuredPeerRow(t)
 for _,kind:=range []string{"early-exit","missing-launcher"} {t.Run(kind,func(t *testing.T){
  f:=configured;_,c,root:=setup(t)
  if kind=="early-exit" {
   helper:=filepath.Join(t.TempDir(),"helper")
   if e:=os.WriteFile(helper,[]byte("#!/bin/sh\nexit 17\n"),0700);e!=nil {t.Fatal(e)};f.PeerHelper=helper
  } else {t.Setenv("PATH",t.TempDir())}
  var row qualification.Case;for _,v:=range qualification.Pending(qualification.Identity{}).Cases {if v.ID=="peer-denied" {row=v}}
  (driver{}).runPeerRows(context.Background(),f,c.Policy,root,&row)
  for _,control:=range []qualification.Control{row.Negative,row.Positive} {
   if control.Executed || control.ExitCode!=-1 || control.Verdict!="pending" {t.Errorf("startup failure gained case execution: fixture=%s recorded=%d executed=%v verdict=%s",kind,control.ExitCode,control.Executed,control.Verdict)}
  }
 })}
}

// Claim: launcher absence remains unrun in the externally emitted driver report,
// not only in the helper-level result. Other rows are intentionally unavailable.
func TestReviewPeerStartupCommand(t *testing.T) {
 f:=configuredPeerRow(t);path,c,root:=setup(t)
 configuration:=filepath.Join(filepath.Dir(path),"roles.json");b,e:=wire.Encode(f);if e!=nil||os.WriteFile(configuration,b,0600)!=nil {t.Fatal("configuration")}
 d:=newFixtureDriver(path,"0.163.0");d.rowExecutable=filepath.Join(root,"unavailable-worker")
 t.Setenv("PATH",t.TempDir())
 var out bytes.Buffer
 if code:=d.run(context.Background(),[]string{"--executable",c.Policy.Executable,"--fixtures","--fixture-config",configuration,"--evidence-dir",root},&out);code!=69 {t.Fatal("driver status",code)}
 var result report;if wire.Decode(bytes.TrimSpace(out.Bytes()),&result)!=nil {t.Fatal("driver report")}
 for _,row:=range result.Cases {if row.ID=="peer-denied" {
  for _,control:=range []qualification.Control{row.Negative,row.Positive} {if control.Executed||control.ExitCode!=-1||control.Verdict!="pending" {t.Errorf("startup failure gained case execution in driver report: recorded=%d executed=%v verdict=%s",control.ExitCode,control.Executed,control.Verdict)}}
  return
 }}
 t.Fatal("missing peer row")
}
