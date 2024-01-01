package main

import (
	"bufio"
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
	Name    string
	Title   string
	Body1   string
	Answer1 string
	Body2   string
	Answer2 string
	Input   string
}

func loadTask(taskName string) (Task, error) {
	dataDir := "data"
	filePath := filepath.Join(dataDir, taskName+".txt")

	file, err := os.Open(filePath)
	defer file.Close()
	if err != nil {
		return Task{}, fmt.Errorf("Failed to open task task %v %v", filePath, err)
	}

	scanner := bufio.NewScanner(file)
	var task Task
	var currentSection string

	task.Name = taskName
	for scanner.Scan() {
		line := scanner.Text()
		switch line {
		case "[title]":
			currentSection = "title"
		case "[body]":
			currentSection = "body1"
		case "[body1]":
			currentSection = "body1"
		case "[answer]":
			currentSection = "answer1"
		case "[answer1]":
			currentSection = "answer1"
		case "[body2]":
			currentSection = "body2"
		case "[answer2]":
			currentSection = "answer2"
		case "[input]":
			currentSection = "input"
		default:
			switch currentSection {
			case "title":
				task.Title = line
			case "body1":
				if line == "<code>" { // quick hack
					task.Body1 += line
				} else {
					task.Body1 += line + "<br>"
				}
			case "body2":
				if line == "<code>" { // quick hack
					task.Body2 += line
				} else {
					task.Body2 += line + "<br>"
				}
			case "answer1":
				task.Answer1 = line
			case "answer2":
				task.Answer2 = line
			case "input":
				task.Input += line + "\n"
			}
		}
	}

	if scanner.Err() != nil {
		return Task{}, fmt.Errorf("Failed to read task %v %v", filePath, err)
	}
	return task, nil
}

func listTaskNames() []string {
	data_dir := "data"
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
		if filepath.Ext(entry.Name()) != ".txt" {
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
	task, err := loadTask(taskName)
	if err != nil {
		http.Error(w, "Can't find task", http.StatusNotFound)
		return
	}

	w.Write([]byte(task.Input))
}

func main() {

	http.HandleFunc("/", BasicAuth(MainPage))

	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("./static"))))

	http.HandleFunc("/input/", BasicAuth(InputFile))

	http.HandleFunc("/task/", BasicAuth(TaskPage))

	http.HandleFunc("/submit/", BasicAuth(SubmitPage))

	http.ListenAndServe(":8080", nil)
}
