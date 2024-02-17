package main

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/peterh/liner"
)

const (
	startUpMessage = "Go Shell - A Repl for Go"
	helpMessage    = `Commands:
	.q(uit)		exit Go Shell
	.v(ars)		show all variable names
	.s(ource)	print the source entered since startup
	.u(ndo)	        undo the last entry
	.h(elp)		print this help message
	`

	_programPath = "program.go"
)

func main() {

	done := make(chan bool, 1)
	go waitForSignal(done)
	commandsChan := make(chan string, 1)
	continueChan := make(chan bool, 1)

	line, history_path := setupLiner()
	defer line.Close()

	fmt.Println(startUpMessage)
	fmt.Println(helpMessage)
	continueChan <- true
	go waitForInput(commandsChan, continueChan, done, line)

	manager := newManager(_programPath)
	manager.cleanUp()

	for {
		select {
		case <-done:
			manager.cleanUp()
			if f, err := os.Create(history_path); err != nil {
				fmt.Println("Error writing history file: ", err)
			} else {
				line.WriteHistory(f)
				f.Close()
			}
			return
		case command := <-commandsChan:
			switch command {
			case ".quit", ".q":
				manager.cleanUp()
				return
			case ".vars", ".v":
				fmt.Println(manager.extractVariables())
			case ".source", ".s":
				program, err := manager.getProgram()
				if err != nil {
					fmt.Println("Error:", err)
				} else {
					fmt.Println(program)
				}
			case ".undo", ".u":
				manager.removeLastInput()
			case ".help", ".h":
				fmt.Println(helpMessage)

			default:
				err := manager.addInput(command)
				if err != nil {
					fmt.Println("Error:", err)
					continueChan <- true
					continue
				}
				output, err := manager.runProgram()
				if err != nil {
					fmt.Println("Removing last input, type '.s(ource)' to see the program.")
					manager.removeLastInput()
				}
				if output != "" {
					fmt.Print(output)
				}
			}
		}
		continueChan <- true
	}
}

func waitForInput(commands chan<- string, continueChan <-chan bool, done chan bool, line *liner.State) {
	for <-continueChan {
		if command, err := line.Prompt(">>> "); err == nil {
			commands <- command
			if command == "exit" {
				done <- true
				return
			} else if command == "" {
				continue
			}
			line.AppendHistory(command)
		} else if err == liner.ErrPromptAborted {
			done <- true
			return
		} else {
			done <- true
		}
	}
}

func waitForSignal(done chan bool) {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	sig := <-sigs
	fmt.Println()
	fmt.Println("received:", sig)
	done <- true

}

func setupLiner() (*liner.State, string) {
	homedir, err := os.UserHomeDir()
	if err != nil {
		fmt.Println("Error getting home directory:", err)
		homedir = os.TempDir()
	}
	history_path := filepath.Join(homedir, ".goshell_history")
	line := liner.NewLiner()
	line.SetCtrlCAborts(true)

	line.SetCompleter(func(line string) (c []string) {
		for _, n := range autoComplete {
			if strings.HasPrefix(n, strings.ToLower(line)) {
				c = append(c, n)
			}
		}
		return
	})

	if f, err := os.Open(history_path); err == nil {
		line.ReadHistory(f)
		f.Close()
	}
	return line, history_path
}
