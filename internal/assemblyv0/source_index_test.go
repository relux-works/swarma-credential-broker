package assemblyv0

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var sourceExcerptHashes = map[string]string{
	"spec/broker.md:391-413":                       "sha256:34bf68a8c5fe8da575727decf732088fad5d934d2f264f535879ce17b37c1aa0",
	"spec/broker.md:441-453":                       "sha256:ae1f530eeafa9a561574d4b47ba82d03d3c720d6237615933e40b95f4bc463d2",
	"spec/broker.md:957-957":                       "sha256:15bcb5730b6a79a0c267555f5fe48aa9656aabb3dde48a6fd7c036cfb813b95d",
	"spec/operator-and-activation-v0.md:1055-1061": "sha256:ad9f183d446cb1bd2429737867383c5123eecc17ff8a40cfc8fa93af0d3ad6cb",
	"spec/operator-and-activation-v0.md:1415-1437": "sha256:e237deb7589b149ee36ba1688e309d2eda941933865e666a8a0b36512f274a7a",
	"spec/operator-and-activation-v0.md:1456-1466": "sha256:4cb8bfce108a0c84889d45a9c4926c9b8f8155b9f60ac876f98ff6d2c9369bea",
	"spec/operator-and-activation-v0.md:1476-1496": "sha256:97ce909458cdb4878f5ac1027af22a7a20e98673c6a6a76091df1cbbfabdca68",
	"spec/operator-and-activation-v0.md:148-151":   "sha256:4aae8f0ae9ebd9d7ecba0602db8ba0060ea34e0b85f62642596cf34b887e5964",
	"spec/operator-and-activation-v0.md:1516-1525": "sha256:024473559df5de38004418261719ca3f96ee3853a008cb17e8f5c2b51f06f065",
	"spec/operator-and-activation-v0.md:1599-1601": "sha256:d794e90a7a0d1cae432ee1c136860f79a6cd1b4d60a4128e7b169f9ff2358e59",
	"spec/operator-and-activation-v0.md:349-364":   "sha256:d2202856912adda422b0733115e714a145edaa09b4ace00b31c09c3e67e20915",
	"spec/operator-and-activation-v0.md:409-433":   "sha256:4394e58f2352f94745901877e84235d6d56f85c9745c367f53ba1600f58d84fe",
	"spec/operator-and-activation-v0.md:424-433":   "sha256:afe6d97704b13cc6abd3e8f09d84dac029360f445c4b0dac6c8605dc73cd4d28",
	"spec/operator-and-activation-v0.md:435-446":   "sha256:fc38abcfb0b9b5d59b21fa552772b32046e84ce0324467ffce6dd90568dacc1e",
	"spec/operator-and-activation-v0.md:447-450":   "sha256:a05e04466fcfec71fdfc681158841fe54a842d0d553020aef690e4f4eb5432cc",
	"spec/operator-and-activation-v0.md:454-488":   "sha256:252b20d64e0e66833f42d061a98c10082920503654eabc5714983fad4fd8cc74",
	"spec/operator-and-activation-v0.md:458-468":   "sha256:464982b5126d9b1d2fd5244927cf45b86031dd68534ead436c4b516698e44b87",
	"spec/operator-and-activation-v0.md:469-474":   "sha256:ba98b600e52a95e8784fcd9b4505295cd4b9e0720534cf62afd88f82ec27204b",
	"spec/operator-and-activation-v0.md:485-503":   "sha256:68e2b74bb5bd5c207b1d9b59c3b257d9d27173df2431ad286cc43d5cdc17ae80",
	"spec/operator-and-activation-v0.md:499-503":   "sha256:3a66f4eec86176722c1ecd93de62b6ff6d413775c69e16e8652fd1780f3628eb",
	"spec/operator-and-activation-v0.md:518-536":   "sha256:8b43fe22038ef02b64c10d09ef26b2342e559fddb340e5b5de46884bc033ccf3",
	"spec/operator-and-activation-v0.md:75-85":     "sha256:bc05c8ae017b64f8f1952ec285e6a90e7d9dec884938625891d86f03f2e28bdb",
	"spec/operator-and-activation-v0.md:785-824":   "sha256:5e105a5d061f1b8936958764ecea55b4db904f5aa2f11d774b7a45a1350cefe5",
	"spec/operator-and-activation-v0.md:81-85":     "sha256:8c041b23658132bef666080c3c37af2cfc1d015e2841de292da78337c45fd6fb",
	"spec/operator-and-activation-v0.md:826-850":   "sha256:7bb302ea0f426a400540d29ee23792d910d398cd2eb4b784d20238e0207f0f14",
	"spec/operator-and-activation-v0.md:91-113":    "sha256:659d2f32778f75a267aacddd8a41943b27f9d98d1e29a2ab1ff2be4992df3a31",
}

var (
	errSourceCitationPath    = errors.New("source citation path is not pinned")
	errSourceCitationRange   = errors.New("source citation line range is invalid")
	errSourceCitationSeal    = errors.New("source citation excerpt seal is invalid")
	errSourceCitationExcerpt = errors.New("source citation excerpt changed; contract rebase required")
)

func sealedSourceReference(path string, first, last int) sourceReference {
	key := fmt.Sprintf("%s:%d-%d", path, first, last)
	return sourceReference{Path: path, FirstLine: first, LastLine: last, ExcerptSHA256: sourceExcerptHashes[key]}
}

func checkSourceExcerpt(source sourceReference, data []byte) error {
	if source.Path != specificationPath && source.Path != "spec/broker.md" {
		return errSourceCitationPath
	}
	lines := bytes.SplitAfter(data, []byte("\n"))
	if len(lines[len(lines)-1]) == 0 {
		lines = lines[:len(lines)-1]
	}
	if source.FirstLine < 1 || source.LastLine < source.FirstLine || source.LastLine > len(lines) {
		return errSourceCitationRange
	}
	seal, err := hex.DecodeString(strings.TrimPrefix(source.ExcerptSHA256, "sha256:"))
	if !strings.HasPrefix(source.ExcerptSHA256, "sha256:") || err != nil || len(seal) != 32 {
		return errSourceCitationSeal
	}
	excerpt := bytes.Join(lines[source.FirstLine-1:source.LastLine], nil)
	if string(digestBytes(excerpt)) != source.ExcerptSHA256 {
		return errSourceCitationExcerpt
	}
	return nil
}

// Claim: source pins verify file content without Git history or a rebase-sensitive commit reference; this is not source-authenticity evidence.
func TestConstructionSourceContentPins(test *testing.T) {
	stored, err := os.ReadFile(filepath.Join(vectorDirectory, "index.json"))
	if err != nil {
		test.Fatal(err)
	}
	var metadata map[string]json.RawMessage
	if err := json.Unmarshal(stored, &metadata); err != nil {
		test.Fatal(err)
	}
	if _, exists := metadata["spec_commit"]; exists {
		test.Fatal("commit-dependent source pin forbidden")
	}
	var index vectorIndex
	if err := json.Unmarshal(stored, &index); err != nil {
		test.Fatal(err)
	}
	for _, source := range []struct {
		path   string
		digest string
	}{
		{"spec/broker.md", index.BaselineSpecSHA256},
		{specificationPath, index.SpecSHA256},
	} {
		test.Run(source.path, func(test *testing.T) {
			data, err := os.ReadFile(filepath.Join("..", "..", source.path))
			if err != nil || string(digestBytes(data)) != "sha256:"+source.digest {
				test.Fatal("source content pin changed")
			}
		})
	}
}

// Claim: every sealed citation resolves to its expected exact LF-inclusive excerpt in the current source, independently of whole-file pins.
func TestConstructionSourceCitations(test *testing.T) {
	stored, err := os.ReadFile(filepath.Join(vectorDirectory, "index.json"))
	if err != nil {
		test.Fatal(err)
	}
	var index vectorIndex
	if err := json.Unmarshal(stored, &index); err != nil {
		test.Fatal(err)
	}
	if len(index.Vectors) == 0 {
		test.Fatal("source index has no vectors")
	}
	for _, vector := range index.Vectors {
		test.Run(vector.File, func(test *testing.T) {
			if len(vector.Sources) == 0 {
				test.Fatal("vector has no source citation")
			}
			for _, source := range vector.Sources {
				if source.Path != specificationPath && source.Path != "spec/broker.md" {
					test.Fatal(errSourceCitationPath)
				}
				data, err := os.ReadFile(filepath.Join("..", "..", source.Path))
				if err != nil {
					test.Fatal(err)
				}
				if err := checkSourceExcerpt(source, data); err != nil {
					test.Errorf("%s:%d-%d: %v", source.Path, source.FirstLine, source.LastLine, err)
				}
			}
		})
	}
}

// Claim: one inserted line in either real source is refused for excerpt drift beside a valid control, independently of whole-file pins.
func TestConstructionSourceCitationLineShift(test *testing.T) {
	for _, source := range []sourceReference{
		sourceLines(1599, 1601),
		sealedSourceReference("spec/broker.md", 957, 957),
	} {
		test.Run(source.Path, func(test *testing.T) {
			data, err := os.ReadFile(filepath.Join("..", "..", source.Path))
			if err != nil {
				test.Fatal(err)
			}
			if err := checkSourceExcerpt(source, data); err != nil {
				test.Fatalf("valid control: %v", err)
			}
			shifted := append([]byte("\n"), data...)
			if err := checkSourceExcerpt(source, shifted); !errors.Is(err, errSourceCitationExcerpt) {
				test.Fatalf("one-line shift: got %v, want %v", err, errSourceCitationExcerpt)
			}
		})
	}
}

// Claim: invalid paths, line bounds and seals fail specifically; valid final lines retain their exact bytes, with or without a terminal LF.
func TestConstructionSourceCitationBoundaries(test *testing.T) {
	data := []byte("first\nlast\n")
	valid := sourceReference{Path: specificationPath, FirstLine: 1, LastLine: 2, ExcerptSHA256: string(digestBytes(data))}
	if err := checkSourceExcerpt(valid, data); err != nil {
		test.Fatalf("valid full-file control: %v", err)
	}
	for _, entry := range []struct {
		name   string
		change func(*sourceReference)
		want   error
	}{
		{"unsealed", func(source *sourceReference) { source.ExcerptSHA256 = "" }, errSourceCitationSeal},
		{"malformed-seal", func(source *sourceReference) { source.ExcerptSHA256 = "sha256:xyz" }, errSourceCitationSeal},
		{"wrong-excerpt", func(source *sourceReference) { source.ExcerptSHA256 = string(digestBytes([]byte("other\n"))) }, errSourceCitationExcerpt},
		{"unpinned-path", func(source *sourceReference) { source.Path = "../other.md" }, errSourceCitationPath},
		{"zero-start", func(source *sourceReference) { source.FirstLine = 0 }, errSourceCitationRange},
		{"reversed", func(source *sourceReference) { source.FirstLine = 2; source.LastLine = 1 }, errSourceCitationRange},
		{"past-last-line", func(source *sourceReference) { source.LastLine = 3 }, errSourceCitationRange},
	} {
		test.Run(entry.name, func(test *testing.T) {
			source := valid
			entry.change(&source)
			if err := checkSourceExcerpt(source, data); !errors.Is(err, entry.want) {
				test.Fatalf("got %v, want %v", err, entry.want)
			}
		})
	}
	for _, body := range []string{"last\n", "last"} {
		source := sourceReference{Path: specificationPath, FirstLine: 1, LastLine: 1, ExcerptSHA256: string(digestBytes([]byte(body)))}
		if err := checkSourceExcerpt(source, []byte(body)); err != nil {
			test.Errorf("valid final-line control %q: %v", body, err)
		}
	}
	if err := checkSourceExcerpt(valid, nil); !errors.Is(err, errSourceCitationRange) {
		test.Fatalf("empty file: got %v, want %v", err, errSourceCitationRange)
	}
}
