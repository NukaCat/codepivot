package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"
)

type Task struct {
	Name    string `json:"name"`
	Title   string `json:"title"`
	Body1   string `json:"body1"`
	Answer1 string `json:"answer1"`
	Body2   string `json:"body2"`
	Answer2 string `json:"answer2"`
	Input   string `json:"-"`
}

func loadTask(taskName string) (Task, error) {
	dataDir := "tasks"
	filePath := filepath.Join(dataDir, taskName+".json")

	file, err := os.Open(filePath)
	defer file.Close()
	if err != nil {
		return Task{}, fmt.Errorf("Failed to open task task %v %v", filePath, err)
	}

	data, err := io.ReadAll(file)
	if err != nil {
		return Task{}, fmt.Errorf("failed to read user file %s %w", filePath, err)
	}

	var task Task
	err = json.Unmarshal(data, &task)
	if err != nil {
		return Task{}, fmt.Errorf("failed to parse json file %s %w", filePath, err)
	}

	return task, nil
}

func saveTask(task Task) error {
	dataDir := "tasks"
	filePath := filepath.Join(dataDir, task.Name+".json")

	jsonData, err := json.MarshalIndent(task, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to save json file %s %w", filePath, err)
	}

	err = os.WriteFile(filePath, jsonData, 0666)
	if err != nil {
		return fmt.Errorf("failed to save json file %s %w", filePath, err)
	}

	return nil
}

func listTaskNames() []string {
	data_dir := "tasks"
	entries, err := os.ReadDir(data_dir)
	if err != nil {
		fmt.Println("failed to find tasks dir")
		return make([]string, 0)
	}

	var taskNames []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		taskName := strings.TrimSuffix(filepath.Base(entry.Name()), filepath.Ext(entry.Name()))
		taskNames = append(taskNames, taskName)
	}
	return taskNames
}

type User struct {
	Name     string         `json:"name"`
	Password string         `json:"password"`
	Progress map[string]int `json:"progress"`
}

func loadUser(userName string) (User, error) {
	filePath := filepath.Join("users", userName+".json")
	file, err := os.Open(filePath)
	if err != nil {
		return User{}, fmt.Errorf("failed to open user file %s %w", filePath, err)
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return User{}, fmt.Errorf("failed to read user file %s %w", filePath, err)
	}

	var user User
	err = json.Unmarshal(data, &user)
	if err != nil {
		return User{}, fmt.Errorf("failed to parse user file %s %w", filePath, err)
	}

	if user.Progress == nil {
		user.Progress = make(map[string]int)
	}

	return user, nil
}

func saveUser(userName string, user User) error {
	filePath := filepath.Join("users", userName+".json")

	jsonData, err := json.MarshalIndent(user, "", "  ")
	if err != nil {
		return err
	}

	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create file %s %w", filePath, err)
	}
	defer file.Close()

	file.Write(jsonData)
	return nil
}

func checkCredentials(username string, password string) bool {
	user, err := loadUser(username)
	if err != nil {
		return false
	}
	if user.Name == username && user.Password == password {
		return true
	}
	return false
}

type UserHandlerFunc func(User, http.ResponseWriter, *http.Request)

func BasicAuth(handler UserHandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		user, err := loadUser(username)
		if err != nil {
			w.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		if user.Name != username || user.Password != password {
			w.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		handler(user, w, r)
	}
}

func MainPage(user User, w http.ResponseWriter, r *http.Request) {
	var notDoneTasks []Task
	var doneTasks []Task

	taskNames := listTaskNames()

	for _, taskName := range taskNames {
		task, err := loadTask(taskName)
		if err != nil {
			log.Println("Can't load task %w", err)
			continue
		}

		done := false
		if task.Body2 == "" {
			done = user.Progress[taskName] > 0
		}
		if task.Body2 != "" {
			done = user.Progress[taskName] > 1
		}

		if done {
			doneTasks = append(doneTasks, task)
		} else {
			notDoneTasks = append(notDoneTasks, task)
		}
	}
	type TasksPage struct {
		DoneTasks    []Task
		NotDoneTasks []Task
	}

	indexTmpl := template.Must(template.ParseFiles("index.html"))
	indexTmpl.Execute(w, TasksPage{DoneTasks: doneTasks, NotDoneTasks: notDoneTasks})
}

func TaskPage(user User, w http.ResponseWriter, r *http.Request) {
	taskSegments := strings.Split(r.URL.Path, "/")
	if len(taskSegments) < 3 {
		http.Error(w, "No task name", http.StatusBadRequest)
		return
	}

	taskName := taskSegments[2]
	task, err := loadTask(taskName)
	if err != nil {
		http.Error(w, "Task not found", http.StatusNotFound)
		return
	}

	type TaskPage struct {
		Task        Task
		Progress    int
		ShowAnswer1 bool
		ShowBody2   bool
		ShowAnswer2 bool
	}
	taskPage := TaskPage{
		Task:        task,
		ShowAnswer1: user.Progress[task.Name] > 0,
		ShowBody2:   user.Progress[task.Name] > 0 && task.Body2 != "",
		ShowAnswer2: user.Progress[task.Name] > 1 && task.Body2 != "",
	}

	taskTmpl := template.Must(template.ParseFiles("task.html"))
	taskTmpl.Execute(w, taskPage)
}

func SubmitPage(user User, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Not post request", http.StatusBadRequest)
		return
	}

	taskSegments := strings.Split(r.URL.Path, "/")
	if len(taskSegments) < 3 {
		http.Error(w, "No task name", http.StatusBadRequest)
		return
	}

	if len(taskSegments) < 4 {
		http.Error(w, "No answer number", http.StatusBadRequest)
		return
	}

	err := r.ParseForm()
	if err != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	answer := r.FormValue("answer")

	taskName := taskSegments[2]
	answerNumber, err := strconv.Atoi(taskSegments[3])
	if err != nil || answerNumber < 0 || answerNumber > 2 {
		http.Error(w, "Bad answer number", http.StatusBadRequest)
	}

	task, err := loadTask(taskName)
	if err != nil {
		http.Error(w, "Failed to load task", http.StatusInternalServerError)
		return
	}

	accepted := false
	if answerNumber == 1 {
		accepted = task.Answer1 == answer
	}
	if answerNumber == 2 {
		accepted = task.Answer2 == answer
	}
	if accepted {
		user.Progress[taskName] = answerNumber
		err = saveUser(user.Name, user)
		if err != nil {
			http.Error(w, "Failed to update user", http.StatusInternalServerError)
			return
		}
	}

	type SubmitPage struct {
		TaskName string
		Accepted bool
	}

	submitPage := SubmitPage{TaskName: taskName, Accepted: accepted}

	submitTpl := template.Must(template.ParseFiles("submit.html"))
	submitTpl.Execute(w, submitPage)
}

func InputFile(user User, w http.ResponseWriter, r *http.Request) {
	taskSegments := strings.Split(r.URL.Path, "/")
	if len(taskSegments) < 3 {
		http.Error(w, "No task name", http.StatusBadRequest)
		return
	}

	taskName := taskSegments[2]
	data, err := os.ReadFile(filepath.Join("tasks", taskName+".input"))
	if err != nil {
		http.Error(w, "Can't load input file", http.StatusNotFound)
		return
	}

	w.Write([]byte(data))
}

func main() {
	http.HandleFunc("/", BasicAuth(MainPage))

	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("./static"))))

	http.HandleFunc("/input/", BasicAuth(InputFile))

	http.HandleFunc("/task/", BasicAuth(TaskPage))

	http.HandleFunc("/submit/", BasicAuth(SubmitPage))

	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		log.Fatalf("Serve error %v", err)
	}
}
