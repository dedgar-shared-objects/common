/*
Copyright 2022 Doug Edgar.

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

package logtypes

// PodLog contains select metadata around a Kubernetes/OpenShift pod
type PodLog struct {
	User      string `json:"user"`
	Namespace string `json:"namespace"`
	PodName   string `json:"podName"`
	HostIP    string `json:"hostIP"`
	PodIP     string `json:"podIP"`
	StartTime int64  `json:"startTime"`
	UUID      string `json:"uuid"`
	ClusterID string `json:"clusterID"`
}

// ScanResult represents a scan result generated by an antivirus scanner.
type ScanResult struct {
	User        string   `json:"user"`
	Namespace   string   `json:"namespace"`
	PodName     string   `json:"podName"`
	HostIP      string   `json:"hostIP"`
	PodIP       string   `json:"podIP"`
	StartTime   int64    `json:"startTime"`
	UUID        string   `json:"uuid"`
	ClusterID   string   `json:"clusterID"`
	ContainerID string   `json:"containerID"`
	ImageID     string   `json:"imageID"`
	ImageName   string   `json:"imageName"`
	ImageSource string   `json:"imageSource"`
	Results     []Result `json:"results"`
}

// Result is the individual result about a file that positively matched an antivirus signature
type Result struct {
	Description    string `json:"description"`
	FilePath       string `json:"filePath"`
	ScannerName    string `json:"scannerName"`
	ScannerVersion string `json:"scannerVersion"`
	SignatureName  string `json:"signatureName"`
	Timestamp      int64  `json:"timestamp"`
}