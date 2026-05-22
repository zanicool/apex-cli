package distributed

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Queue is a file-based job queue for distributed scanning
type Queue struct {
	dir     string
	mu      sync.Mutex
	workerID string
}

type Job struct {
	ID       string    `json:"id"`
	Domain   string    `json:"domain"`
	Program  string    `json:"program"`
	Status   string    `json:"status"` // "pending", "running", "done", "failed"
	Worker   string    `json:"worker"`
	Created  time.Time `json:"created"`
	Started  time.Time `json:"started,omitempty"`
	Finished time.Time `json:"finished,omitempty"`
	Findings int       `json:"findings"`
	Error    string    `json:"error,omitempty"`
}

// NewQueue creates a queue backed by a shared directory (NFS, sshfs, or local)
func NewQueue(dir, workerID string) *Queue {
	os.MkdirAll(filepath.Join(dir, "pending"), 0755)
	os.MkdirAll(filepath.Join(dir, "running"), 0755)
	os.MkdirAll(filepath.Join(dir, "done"), 0755)
	os.MkdirAll(filepath.Join(dir, "failed"), 0755)
	return &Queue{dir: dir, workerID: workerID}
}

// Enqueue adds a job to the queue
func (q *Queue) Enqueue(domain, program string) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	job := Job{
		ID:      fmt.Sprintf("%s_%d", safeDomain(domain), time.Now().UnixNano()),
		Domain:  domain,
		Program: program,
		Status:  "pending",
		Created: time.Now(),
	}
	data, _ := json.Marshal(job)
	return os.WriteFile(filepath.Join(q.dir, "pending", job.ID+".json"), data, 0644)
}

// EnqueueBatch adds multiple jobs
func (q *Queue) EnqueueBatch(targets []struct{ Domain, Program string }) int {
	count := 0
	for _, t := range targets {
		if q.Enqueue(t.Domain, t.Program) == nil {
			count++
		}
	}
	return count
}

// Dequeue claims the next pending job for this worker
func (q *Queue) Dequeue() (*Job, error) {
	q.mu.Lock()
	defer q.mu.Unlock()

	entries, err := os.ReadDir(filepath.Join(q.dir, "pending"))
	if err != nil || len(entries) == 0 {
		return nil, fmt.Errorf("no jobs available")
	}

	// Take the first one (FIFO)
	entry := entries[0]
	pendingPath := filepath.Join(q.dir, "pending", entry.Name())
	data, err := os.ReadFile(pendingPath)
	if err != nil {
		return nil, err
	}

	var job Job
	json.Unmarshal(data, &job)
	job.Status = "running"
	job.Worker = q.workerID
	job.Started = time.Now()

	// Move to running
	runningPath := filepath.Join(q.dir, "running", entry.Name())
	newData, _ := json.Marshal(job)
	os.WriteFile(runningPath, newData, 0644)
	os.Remove(pendingPath)

	return &job, nil
}

// Complete marks a job as done
func (q *Queue) Complete(job *Job, findings int) {
	q.mu.Lock()
	defer q.mu.Unlock()
	job.Status = "done"
	job.Finished = time.Now()
	job.Findings = findings

	data, _ := json.Marshal(job)
	os.WriteFile(filepath.Join(q.dir, "done", job.ID+".json"), data, 0644)
	os.Remove(filepath.Join(q.dir, "running", job.ID+".json"))
}

// Fail marks a job as failed
func (q *Queue) Fail(job *Job, errMsg string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	job.Status = "failed"
	job.Finished = time.Now()
	job.Error = errMsg

	data, _ := json.Marshal(job)
	os.WriteFile(filepath.Join(q.dir, "failed", job.ID+".json"), data, 0644)
	os.Remove(filepath.Join(q.dir, "running", job.ID+".json"))
}

// Stats returns queue statistics
func (q *Queue) Stats() (pending, running, done, failed int) {
	count := func(subdir string) int {
		entries, _ := os.ReadDir(filepath.Join(q.dir, subdir))
		return len(entries)
	}
	return count("pending"), count("running"), count("done"), count("failed")
}

// RecoverStale moves jobs that have been running too long back to pending
func (q *Queue) RecoverStale(maxAge time.Duration) int {
	q.mu.Lock()
	defer q.mu.Unlock()
	recovered := 0
	entries, _ := os.ReadDir(filepath.Join(q.dir, "running"))
	for _, entry := range entries {
		path := filepath.Join(q.dir, "running", entry.Name())
		data, _ := os.ReadFile(path)
		var job Job
		json.Unmarshal(data, &job)
		if time.Since(job.Started) > maxAge {
			job.Status = "pending"
			job.Worker = ""
			newData, _ := json.Marshal(job)
			os.WriteFile(filepath.Join(q.dir, "pending", entry.Name()), newData, 0644)
			os.Remove(path)
			recovered++
		}
	}
	return recovered
}

// --- HTTP API for remote workers ---

// Server exposes the queue over HTTP so remote workers can pull jobs
type Server struct {
	queue *Queue
	port  int
}

func NewServer(queue *Queue, port int) *Server {
	return &Server{queue: queue, port: port}
}

func (s *Server) Start() {
	mux := http.NewServeMux()
	mux.HandleFunc("/job/next", s.handleNext)
	mux.HandleFunc("/job/complete", s.handleComplete)
	mux.HandleFunc("/job/fail", s.handleFail)
	mux.HandleFunc("/stats", s.handleStats)
	go http.ListenAndServe(fmt.Sprintf(":%d", s.port), mux)
}

func (s *Server) handleNext(w http.ResponseWriter, r *http.Request) {
	job, err := s.queue.Dequeue()
	if err != nil {
		http.Error(w, `{"error":"no jobs"}`, 404)
		return
	}
	json.NewEncoder(w).Encode(job)
}

func (s *Server) handleComplete(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID       string `json:"id"`
		Findings int    `json:"findings"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	job := &Job{ID: req.ID}
	s.queue.Complete(job, req.Findings)
	w.Write([]byte(`{"ok":true}`))
}

func (s *Server) handleFail(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID    string `json:"id"`
		Error string `json:"error"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	job := &Job{ID: req.ID}
	s.queue.Fail(job, req.Error)
	w.Write([]byte(`{"ok":true}`))
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	p, run, d, f := s.queue.Stats()
	json.NewEncoder(w).Encode(map[string]int{"pending": p, "running": run, "done": d, "failed": f})
}

// --- Worker client (runs on remote machines) ---

type Worker struct {
	serverURL string
	workerID  string
	client    *http.Client
}

func NewWorker(serverURL, workerID string) *Worker {
	return &Worker{
		serverURL: strings.TrimSuffix(serverURL, "/"),
		workerID:  workerID,
		client:    &http.Client{Timeout: 10 * time.Second},
	}
}

// FetchJob gets the next job from the server
func (w *Worker) FetchJob() (*Job, error) {
	resp, err := w.client.Get(w.serverURL + "/job/next")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("no jobs")
	}
	var job Job
	json.NewDecoder(resp.Body).Decode(&job)
	return &job, nil
}

// ReportComplete reports job completion
func (w *Worker) ReportComplete(jobID string, findings int) {
	data, _ := json.Marshal(map[string]interface{}{"id": jobID, "findings": findings})
	w.client.Post(w.serverURL+"/job/complete", "application/json", strings.NewReader(string(data)))
}

// ReportFail reports job failure
func (w *Worker) ReportFail(jobID, errMsg string) {
	data, _ := json.Marshal(map[string]interface{}{"id": jobID, "error": errMsg})
	w.client.Post(w.serverURL+"/job/fail", "application/json", strings.NewReader(string(data)))
}

func safeDomain(s string) string {
	r := strings.NewReplacer(".", "_", "/", "_", ":", "_", "*", "")
	return r.Replace(s)
}
