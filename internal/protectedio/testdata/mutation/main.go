package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type mutant struct {
	ID, File, Operator, Before, After string
	Line, Start, End                  int
}

type result struct {
	mutant
	Status, Tests, Log  string
	Exit, PID           int
	Load                float64
	ProofLog, ProofTest string
	ProofExit, ProofPID int
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func inventory(root string) []mutant {
	var mutations []mutant
	seen := map[string]bool{}
	for _, path := range []string{"internal/protectedio/read_linux.go", "internal/authorityv0/reader_linux.go"} {
		source, err := os.ReadFile(filepath.Join(root, path))
		must(err)
		positions := token.NewFileSet()
		parsed, err := parser.ParseFile(positions, path, source, 0)
		must(err)
		text := func(node ast.Node) string {
			return string(source[positions.Position(node.Pos()).Offset:positions.Position(node.End()).Offset])
		}
		add := func(node ast.Node, operator, replacement string) {
			start, end := positions.Position(node.Pos()).Offset, positions.Position(node.End()).Offset
			key := fmt.Sprintf("%s:%d:%d:%s", path, start, end, replacement)
			if seen[key] {
				return
			}
			seen[key] = true
			mutations = append(mutations, mutant{File: path, Line: positions.Position(node.Pos()).Line, Operator: operator, Before: text(node), After: replacement, Start: start, End: end})
		}
		values := func(node ast.Node, field string) {
			add(node, "policy-"+field+"-zero", "0")
			broker := os.Geteuid()
			if strings.Contains(strings.ToLower(field), "gid") {
				broker = os.Getegid()
			}
			add(node, "policy-"+field+"-broker", strconv.Itoa(broker))
		}
		ast.Inspect(parsed, func(node ast.Node) bool {
			switch node := node.(type) {
			case *ast.IfStmt:
				add(node.Cond, "decision-negate", "!("+text(node.Cond)+")")
			case *ast.ForStmt:
				if node.Cond != nil {
					add(node.Cond, "decision-negate", "!("+text(node.Cond)+")")
				}
			case *ast.BinaryExpr:
				negated := map[token.Token]string{token.EQL: "!=", token.NEQ: "==", token.LSS: ">=", token.GEQ: "<", token.LEQ: ">", token.GTR: "<="}
				if operator, ok := negated[node.Op]; ok {
					add(node, "comparison-negate", "("+text(node.X)+" "+operator+" "+text(node.Y)+")")
					masked := false
					ast.Inspect(node, func(child ast.Node) bool {
						if binary, ok := child.(*ast.BinaryExpr); ok && (binary.Op == token.AND || binary.Op == token.AND_NOT) && strings.Contains(strings.ToLower(text(binary.X)), "mode") {
							masked = true
						}
						return true
					})
					if masked {
						add(node, "mask-test-constant-true", "true")
						add(node, "mask-test-constant-false", "false")
					}
				}
				if node.Op == token.LAND || node.Op == token.LOR {
					neutral := "false"
					guard := "&&"
					if node.Op == token.LAND {
						neutral, guard = "true", "||"
					}
					add(node, "boolean-drop-left", "(("+neutral+" "+guard+" ("+text(node.X)+")) "+node.Op.String()+" ("+text(node.Y)+"))")
					add(node, "boolean-drop-right", "(("+text(node.X)+") "+node.Op.String()+" ("+neutral+" "+guard+" ("+text(node.Y)+")))")
				}
				if (node.Op == token.AND || node.Op == token.AND_NOT) && strings.Contains(strings.ToLower(text(node.X)), "mode") {
					add(node, "mask-complement", "^("+text(node)+")")
					add(node, "mask-constant-zero", "0")
					add(node, "mask-constant-ones", "("+text(node.X)+" | "+text(node.Y)+")")
					if literal, ok := node.Y.(*ast.BasicLit); ok && node.Op == token.AND {
						mask, err := strconv.ParseUint(literal.Value, 0, 64)
						if err == nil {
							for bit := uint(0); bit < 32; bit++ {
								if mask&(1<<bit) != 0 {
									add(node, fmt.Sprintf("mask-drop-bit-%d", bit), "("+text(node.X)+" & "+strconv.FormatUint(mask&^(1<<bit), 10)+")")
								}
							}
						}
					}
				}
			case *ast.SelectorExpr:
				field, base := node.Sel.Name, text(node.X)
				if (strings.Contains(strings.ToLower(base), "policy") && (field == "UID" || field == "GID" || field == "Mode" || field == "Links" || field == "MaxBytes")) || (base == "reader" && (field == "rootUID" || field == "rootGID" || field == "brokerUID" || field == "brokerGID")) || field == "ancestorUID" {
					values(node, field)
				}
			case *ast.CompositeLit:
				if node.Type != nil && strings.HasSuffix(text(node.Type), "FilePolicy") {
					for _, element := range node.Elts {
						if entry, ok := element.(*ast.KeyValueExpr); ok {
							values(entry.Value, text(entry.Key))
						}
					}
				}
			case *ast.Ident:
				if (node.Name == "owner" || node.Name == "ancestorUID") && node.Obj != nil && node.Pos() != node.Obj.Pos() {
					values(node, node.Name)
				}
			}
			return true
		})
		if strings.Contains(path, "protectedio") {
			for _, entry := range []struct{ before, after, operator string }{
				{"stat.Mode&07022 != 0", "stat.Mode&07020 != 0", "finding-ancestor-mode-bits-unwitnessed"},
				{"stat.Mode&07022 != 0", "stat.Mode&00022 != 0", "finding-ancestor-special-bits"},
				{"metadata.UID != policy.UID || ", "", "finding-leaf-owner-comparison-unwitnessed"},
				{"metadata.Mode != fs.ModeDir|policy.Mode", "metadata.Mode&(fs.ModeDir|fs.ModePerm) != fs.ModeDir|policy.Mode", "finding-directory-mode-special-bits-unwitnessed"},
				{"metadata.Mode != fs.ModeDir|policy.Mode", "metadata.Mode&^(fs.ModeSetuid|fs.ModeSetgid|fs.ModeSticky) != fs.ModeDir|policy.Mode", "finding-directory-special-bits-unwitnessed"},
			} {
				start := bytes.Index(source, []byte(entry.before))
				if start < 0 {
					panic("finding mutation anchor missing")
				}
				mutations = append(mutations, mutant{File: path, Line: bytes.Count(source[:start], []byte("\n")) + 1, Operator: entry.operator, Before: entry.before, After: entry.after, Start: start, End: start + len(entry.before)})
			}
		}
	}
	for index := range mutations {
		mutations[index].ID = fmt.Sprintf("M%04d", index+1)
	}
	return mutations
}

func copySource(root, scratch string) {
	must(filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if entry.IsDir() && (entry.Name() == ".git" || entry.Name() == ".temp") {
			return filepath.SkipDir
		}
		destination := filepath.Join(scratch, relative)
		if entry.IsDir() {
			return os.MkdirAll(destination, 0700)
		}
		if entry.Type()&os.ModeSymlink != 0 {
			target, err := os.Readlink(path)
			if err != nil {
				return err
			}
			return os.Symlink(target, destination)
		}
		contents, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(destination, contents, 0600)
	}))
}

func run(scratch, log string, selection ...string) (int, int, float64) {
	load := 100.0
	for load >= 10 {
		contents, err := os.ReadFile("/proc/loadavg")
		must(err)
		_, err = fmt.Sscan(string(contents), &load)
		must(err)
		if load >= 10 {
			time.Sleep(5 * time.Second)
		}
	}
	output, err := os.Create(log)
	must(err)
	defer output.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	arguments := []string{"test", "-count=1"}
	if len(selection) > 0 {
		arguments = append(arguments, "-run", "^"+regexp.QuoteMeta(selection[0])+"$")
	}
	arguments = append(arguments, "./internal/protectedio", "./internal/authorityv0")
	command := exec.CommandContext(ctx, "go", arguments...)
	command.Dir, command.Stdout, command.Stderr = scratch, output, output
	must(command.Start())
	process := command.Process.Pid
	err = command.Wait()
	if err == nil {
		return 0, process, load
	}
	if ctx.Err() != nil {
		return 124, process, load
	}
	if exit, ok := err.(*exec.ExitError); ok {
		return exit.ExitCode(), process, load
	}
	panic(err)
}

func main() {
	root := flag.String("root", ".", "source root")
	scratch := flag.String("scratch", "", "new, task-owned scratch directory")
	output := flag.String("output", "", "JSONL receipt path")
	only := flag.String("only", "", "optional comma-separated mutant IDs")
	list := flag.Bool("list", false, "enumerate without running")
	flag.Parse()
	syscall.Umask(0022)
	absolute, err := filepath.Abs(*root)
	must(err)
	*root = absolute
	mutations := inventory(*root)
	if *list {
		encoder := json.NewEncoder(os.Stdout)
		for _, mutation := range mutations {
			must(encoder.Encode(mutation))
		}
		return
	}
	if *scratch == "" || *output == "" {
		panic("scratch and output are required")
	}
	absolute, err = filepath.Abs(*scratch)
	must(err)
	*scratch = absolute
	if _, err := os.Stat(*scratch); !os.IsNotExist(err) {
		panic("scratch must not exist")
	}
	must(os.MkdirAll(*scratch, 0700))
	copySource(*root, *scratch)
	receipt, err := os.Create(*output)
	must(err)
	defer receipt.Close()
	encoder := json.NewEncoder(receipt)
	manifest := map[string]string{}
	must(filepath.WalkDir(*scratch, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		if strings.HasSuffix(path, ".go") || entry.Name() == "go.mod" || entry.Name() == "go.sum" {
			contents, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			sum := sha256.Sum256(contents)
			relative, err := filepath.Rel(*scratch, path)
			if err != nil {
				return err
			}
			manifest[relative] = hex.EncodeToString(sum[:])
		}
		return nil
	}))
	must(encoder.Encode(map[string]any{"go_source_sha256": manifest}))
	baseline, process, load := run(*scratch, *output+".control.log")
	must(encoder.Encode(map[string]any{"control_exit": baseline, "pid": process, "load": load, "umask": "022", "broker_uid": os.Geteuid(), "broker_gid": os.Getegid(), "command": "go test -count=1 ./internal/protectedio ./internal/authorityv0"}))
	if baseline != 0 {
		panic("valid control failed")
	}
	failures := regexp.MustCompile(`--- FAIL: ([^\s]+)`)
	unresolved := 0
	for _, mutation := range mutations {
		if *only != "" && !strings.Contains(","+*only+",", ","+mutation.ID+",") {
			continue
		}
		original, err := os.ReadFile(filepath.Join(*root, mutation.File))
		must(err)
		changed := append(append(append([]byte{}, original[:mutation.Start]...), []byte(mutation.After)...), original[mutation.End:]...)
		must(os.WriteFile(filepath.Join(*scratch, mutation.File), changed, 0600))
		log := *output + "." + mutation.ID + ".log"
		exit, pid, load := run(*scratch, log)
		must(os.WriteFile(filepath.Join(*scratch, mutation.File), original, 0600))
		contents, err := os.ReadFile(log)
		must(err)
		status := "SURVIVED"
		var tests []string
		for _, match := range failures.FindAllStringSubmatch(string(contents), -1) {
			tests = append(tests, match[1])
		}
		if exit != 0 {
			status = "ERROR"
			if exit == 1 && len(tests) > 0 && !bytes.Contains(contents, []byte("panic:")) {
				status = "KILLED"
			}
		}
		if mutation.Before == mutation.After {
			status = "EQUIVALENT-SYNTACTIC"
		}
		entry := result{mutant: mutation, Status: status, Tests: strings.Join(tests, ","), Exit: exit, PID: pid, Load: load, Log: filepath.Base(log), ProofExit: -1}
		if status == "ERROR" && bytes.Contains(contents, []byte("panic:")) {
			for _, test := range tests {
				name := strings.Split(test, "/")[0]
				if !strings.HasPrefix(name, "TestMechanical") {
					continue
				}
				must(os.WriteFile(filepath.Join(*scratch, mutation.File), changed, 0600))
				proof := log + ".assertion.log"
				proofExit, proofPID, _ := run(*scratch, proof, name)
				must(os.WriteFile(filepath.Join(*scratch, mutation.File), original, 0600))
				proofContents, err := os.ReadFile(proof)
				must(err)
				entry.ProofLog, entry.ProofTest, entry.ProofExit, entry.ProofPID = filepath.Base(proof), name, proofExit, proofPID
				if proofExit == 1 && failures.Match(proofContents) && !bytes.Contains(proofContents, []byte("panic:")) {
					entry.Status = "KILLED"
					entry.Tests = name
				}
				break
			}
		}
		if entry.Status == "SURVIVED" || entry.Status == "ERROR" {
			unresolved++
		}
		must(encoder.Encode(entry))
		must(receipt.Sync())
		fmt.Printf("%s %s %s:%d %s\n", mutation.ID, entry.Status, mutation.File, mutation.Line, mutation.Operator)
	}
	for _, path := range []string{"internal/protectedio/read_linux.go", "internal/authorityv0/reader_linux.go"} {
		contents, err := os.ReadFile(filepath.Join(*root, path))
		must(err)
		hash := sha256.Sum256(contents)
		must(encoder.Encode(map[string]string{"source": path, "sha256": hex.EncodeToString(hash[:])}))
	}
	if unresolved > 0 {
		fmt.Fprintf(os.Stderr, "unresolved mutations: %d\n", unresolved)
		os.Exit(2)
	}
}
