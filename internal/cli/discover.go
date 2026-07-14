package cli

import (
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// source is one input to scan: a display name and the raw bytes.
type source struct {
	name string
	data []byte
}

// csvExts are the extensions collected when a directory is scanned.
var csvExts = map[string]bool{".csv": true, ".tsv": true, ".psv": true}

// collect resolves the positional arguments into ordered sources. A path of
// "-" (or no paths, when allowStdin) reads stdin. Directories are walked for
// CSV-family files. Results are deterministic: directory walks are sorted.
func collect(paths []string, stdin io.Reader, allowStdin bool) ([]source, error) {
	if len(paths) == 0 {
		if allowStdin {
			data, err := io.ReadAll(stdin)
			if err != nil {
				return nil, err
			}
			return []source{{name: "<stdin>", data: data}}, nil
		}
		return nil, nil
	}

	var out []source
	for _, p := range paths {
		if p == "-" {
			data, err := io.ReadAll(stdin)
			if err != nil {
				return nil, err
			}
			out = append(out, source{name: "<stdin>", data: data})
			continue
		}
		info, err := os.Stat(p)
		if err != nil {
			return nil, err
		}
		if info.IsDir() {
			files, err := walkCSV(p)
			if err != nil {
				return nil, err
			}
			for _, f := range files {
				data, err := os.ReadFile(f)
				if err != nil {
					return nil, err
				}
				out = append(out, source{name: f, data: data})
			}
			continue
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		out = append(out, source{name: p, data: data})
	}
	return out, nil
}

// walkCSV returns every CSV-family file under dir, sorted.
func walkCSV(dir string) ([]string, error) {
	var files []string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if csvExts[strings.ToLower(filepath.Ext(path))] {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	return files, nil
}
