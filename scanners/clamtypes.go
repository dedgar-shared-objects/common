/*
Copyright 2019 Doug Edgar.

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

package scanners

import (
	"context"
	"os"

	"github.com/dedgar-shared-objects/common/logtypes"
	"github.com/openshift/clam-scanner/pkg/clamav"
)

const (
	ScannerName               = "clamav"
	DefaultResultsAPIVersion  = "v1alpha"
	DefaultClamSocketLocation = "/clam/clamd.sock"
)

// FilesFilter desribes callback to filter files.
type FilesFilter func(string, os.FileInfo) bool

// Scanner interface that all scanners should define.
type Scanner interface {
	// Scan will perform a scan on the given path for the given Image.
	// It should return compacted results for JSON serialization and additionally scanner
	// specific results with more details. The context object can be used to cancel the scanning process.
	Scan(ctx context.Context, path string, filter FilesFilter) ([]logtypes.Result, interface{}, error)

	// Name is the scanner's name
	Name() string
}

// ClamScanner is a structure of two vars
// Socket is the location of the clamav socket.
// clamd is a new clamav ClamdSession
type ClamScanner struct {
	Socket string

	clamd clamav.ClamdSession
}

// defaultManagedScanner is the default implementation of ManagedScanner.
type defaultManagedScanner struct {
	opts ManagedScannerOptions
	//ScanOutputs ScanOutputs
	ScanResults logtypes.ScanResult
}

// ManagedScannerOptions is the main scanner implementation and holds the configuration
// for a clam scanner.
type ManagedScannerOptions struct {
	// ScanDir is the name of the directory to be scanned.
	ScanDir string
	// ClamSocket is the location of clamav socket file
	ClamSocket string
}
