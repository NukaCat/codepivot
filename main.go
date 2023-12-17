package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"text/template"
)

type Task struct {
	Name   string
	Title  string
	Body   string
	Answer string
	Input  string
}

func parseTaskFile(filePath string) Task {
	file, err := os.Open(filePath)
	defer file.Close()
	if err != nil {
		panic(fmt.Sprintf("Failed to open task %v %v", filePath, err))
	}

	scanner := bufio.NewScanner(file)
	var task Task
	var currentSection string

	task.Name = strings.TrimSuffix(filepath.Base(filePath), filepath.Ext(filePath))
	for scanner.Scan() {
		line := scanner.Text()
		switch line {
		case "[title]":
			currentSection = "title"
		case "[body]":
			currentSection = "body"
		case "[answer]":
			currentSection = "answer"
		case "[input]":
			currentSection = "input"
		default:
			switch currentSection {
			case "title":
				task.Title = line
			case "body":
				task.Body += line + "<br>"
			case "answer":
				task.Answer = line
			case "input":
				task.Input += line + "\n"
			}
		}
	}

	if scanner.Err() != nil {
		panic(fmt.Sprintf("Failed to read task %v %v", filePath, err))
	}
	return task
}

func loadTasks() ([]Task, error) {
	data_dir := "./data"
	entries, err := os.ReadDir(data_dir)
	if err != nil {
		return nil, fmt.Errorf("failed find ./data dir %w", err)
	}

	var tasks []Task
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if filepath.Ext(entry.Name()) != ".txt" {
			continue
		}
		path := filepath.Join(data_dir, entry.Name())
		task := parseTaskFile(path)
		tasks = append(tasks, task)
	}
	return tasks, nil
}

type User struct {
	Name      string   `json:"name"`
	Password  string   `json:"password"`
	DoneTasks []string `json:"done"`
}

func loadUsers(filePath string) ([]User, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open users file %s %w", filePath, err)
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read users file %s %w", filePath, err)
	}

	var users []User

	err = json.Unmarshal(data, &users)
	if err != nil {
		return nil, fmt.Errorf("failed to parse users file %s %w", filePath, err)
	}

	return users, nil
}

func checkCredentials(username string, password string, users []User) bool {
	for _, user := range users {
		if user.Name == username && user.Password == password {
			return true
		}
	}
	return false
}

func checkUserDoneTask(userName string, taskName string) bool {
	userPath := userName + ".user"
	file, err := os.Open(userPath)
	if err != nil {
		return false
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		if line == taskName {
			return true
		}
	}
	return false
}

func markTaskDone(userName string, taskName string) {
	userPath := userName + ".user"
	f, err := os.OpenFile(userPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()

	_, err = f.WriteString(taskName + "\n")
}

type UserHandlerFunc func(string, http.ResponseWriter, *http.Request)

func BasicAuth(users []User, handler UserHandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok || !checkCredentials(username, password, users) {
			w.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		handler(username, w, r)
	}
}

func main() {
	tasks, err := loadTasks()
	if err != nil {
		panic(err)
	}
	users, err := loadUsers("users.json")
	if err != nil {
		panic(err)
	}

	index_tmpl := template.Must(template.ParseFiles("index.html"))
	task_tmpl := template.Must(template.ParseFiles("task.html"))
	submit_tpl := template.Must(template.ParseFiles("submit.html"))

	http.HandleFunc("/", BasicAuth(users, func(user string, w http.ResponseWriter, r *http.Request) {
		index_tmpl.Execute(w, tasks)
	}))

	http.HandleFunc("/input/", BasicAuth(users, func(user string, w http.ResponseWriter, r *http.Request) {
		taskSegments := strings.Split(r.URL.Path, "/")
		if len(taskSegments) < 3 {
			http.Error(w, "No task name", http.StatusBadRequest)
			return
		}

		taskName := taskSegments[2]
		var task *Task

		for idx, _ := range tasks {
			if tasks[idx].Name == taskName {
				task = &tasks[idx]
			}
		}

		if task == nil {
			http.Error(w, "Can't find task", http.StatusNotFound)
			return
		}

		w.Write([]byte(task.Input))
	}))

	http.HandleFunc("/task/", BasicAuth(users, func(user string, w http.ResponseWriter, r *http.Request) {
		taskSegments := strings.Split(r.URL.Path, "/")
		if len(taskSegments) < 3 {
			http.Error(w, "No task name", http.StatusBadRequest)
			return
		}

		taskName := taskSegments[2]
		var task *Task

		for idx, _ := range tasks {
			if tasks[idx].Name == taskName {
				task = &tasks[idx]
			}
		}

		if task == nil {
			http.Error(w, "Can't find task", http.StatusNotFound)
			return
		}

		done := checkUserDoneTask(user, taskName)

		type TaskPage struct {
			Task Task
			Done bool
		}
		taskPage := TaskPage{Task: *task, Done: done}

		task_tmpl.Execute(w, taskPage)
	}))

	http.HandleFunc("/submit/", BasicAuth(users, func(user string, w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Not post request", http.StatusBadRequest)
			return
		}

		taskSegments := strings.Split(r.URL.Path, "/")
		if len(taskSegments) < 3 {
			http.Error(w, "No task name", http.StatusBadRequest)
			return
		}

		taskName := taskSegments[2]

		err := r.ParseForm()
		if err != nil {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		answer := r.FormValue("answer")

		accept := false
		for _, task := range tasks {
			if task.Name == taskName && task.Answer == answer {
				accept = true
			}
		}

		if accept {
			markTaskDone(user, taskName)
		}

		type SubmitPage struct {
			TaskName string
			Accepted bool
		}

		submitPage := SubmitPage{TaskName: taskName, Accepted: accept}
		submit_tpl.Execute(w, submitPage)
	}))

	http.ListenAndServe(":8080", nil)
}
