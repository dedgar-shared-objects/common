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
	"fmt"
	"strings"
	"time"

	"github.com/dedgar-shared-objects/common/logtypes"
	"github.com/openshift/clam-scanner/pkg/clamav"
)

// NewScanner initializes a new clamd session
func NewScanner(socket string) (Scanner, error) {
	clamSession, err := clamav.NewClamdSession(socket, true)
	if err != nil {
		fmt.Println("NewScanner error")
		return nil, fmt.Errorf("Error creating NewClamdSession: %v\n", err)
	}

	return &ClamScanner{
		Socket: socket,
		clamd:  clamSession,
	}, nil
}

// Scan will scan the image
func (s *ClamScanner) Scan(ctx context.Context, path string, filter FilesFilter) ([]logtypes.Result, interface{}, error) {
	scanResults := []logtypes.Result{}

	scanStarted := time.Now()

	defer func() {
		fmt.Printf("clamav scan took %ds (%d problems found)\n", int64(time.Since(scanStarted).Seconds()), len(scanResults))
	}()

	if err := s.clamd.ScanPath(ctx, path, clamav.FilterFiles(filter)); err != nil {
		return nil, nil, err
	}

	s.clamd.WaitTillDone()
	defer s.clamd.Close()

	clamResults := s.clamd.GetResults()

	for _, r := range clamResults.Files {
		r := logtypes.Result{
			ScannerName: ScannerName,
			Timestamp:   scanStarted.Unix(),
			FilePath:    fmt.Sprintf("file://%s", strings.TrimPrefix(r.Filename, path)),
			Description: r.Result,
		}
		scanResults = append(scanResults, r)
	}
	fmt.Printf("clamav results: %+v\n", scanResults)
	return scanResults, nil, nil
}

// Name returns the const ScannerName
func (s *ClamScanner) Name() string {
	return ScannerName
}

// NewDefaultManagedScanner provides a new default scanner.
func NewDefaultManagedScanner(opts ManagedScannerOptions) *defaultManagedScanner {
	ManagedScanner := &defaultManagedScanner{
		opts: opts,
	}

	ManagedScanner.ScanResults = logtypes.ScanResult{
		Results: []logtypes.Result{},
	}

	return ManagedScanner
}

// AcquireAndScan scans based on the ManagedScannerOptions.
func (i *defaultManagedScanner) StartClamScan() ([]logtypes.Result, error) {
	var filterFn FilesFilter

	ctx := context.Background()

	scanner, err := NewScanner(i.opts.ClamSocket)
	if err != nil {
		return []logtypes.Result{}, fmt.Errorf("Failed to initialize NewScanner: %v", err)
	}

	results, _, err := scanner.Scan(ctx, i.opts.ScanDir, filterFn)
	if err != nil {
		return []logtypes.Result{}, fmt.Errorf("Error: unable to scan directory %q with ClamAV: %v", i.opts.ScanDir, err)
	}

	i.ScanResults.Results = append(i.ScanResults.Results, results...)

	if len(i.ScanResults.Results) > 0 {
		fmt.Println("Infected files found: ", i.ScanResults.Results)
		return i.ScanResults.Results, nil
	}

	fmt.Println("The results slice was empty: ", i.ScanResults.Results)

	return []logtypes.Result{}, nil
}

// NewDefaultManagedScannerOptions provides a new ManagedScannerOptions with default values.
func NewDefaultManagedScannerOptions() *ManagedScannerOptions {
	return &ManagedScannerOptions{
		ScanDir:    "",
		ClamSocket: DefaultClamSocketLocation,
	}
}

// Validate performs validation on the field settings.
func (i *ManagedScannerOptions) Validate() error {
	if len(i.ScanDir) == 0 {
		return fmt.Errorf("a directory to scan must be specified.")
	}
	return nil
}
