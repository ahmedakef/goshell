package main

import (
	"bufio"
	"fmt"
	"os"
	"os/signal"
	"syscall"
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
	continueChan <- true
	go waitForInput(commandsChan, continueChan, done)

	manager := newManager(_programPath)
	manager.cleanUp()

	fmt.Println(startUpMessage)
	fmt.Println(helpMessage)
	for {
		select {
		case <-done:
			manager.cleanUp()
			return
		case command := <-commandsChan:
			switch command {
			case ".quit", ".q":
				manager.cleanUp()
				return
			case ".vars", ".v":
				fmt.Println(manager.extractVariables())
				continueChan <- true
				continue
			case ".source", ".s":
				program, err := manager.getProgram()
				if err != nil {
					fmt.Println("Error:", err)
				} else {
					fmt.Println(program)
				}
				continueChan <- true
				continue
			case ".undo", ".u":
				manager.removeLastInput()
				continueChan <- true
				continue
			case ".help", ".h":
				fmt.Println(helpMessage)
				continueChan <- true
				continue
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
				continueChan <- true
			}
		}
	}
}

func waitForInput(commands chan<- string, continueChan <-chan bool, done chan bool) {
	scanner := bufio.NewScanner(os.Stdin)
	for <-continueChan {
		fmt.Print(">>> ")
		scanned := scanner.Scan()
		if !scanned {
			if scanner.Err() != nil {
				fmt.Println("Error:", scanner.Err())
			}
			done <- true
			return
		}
		command := scanner.Text()

		if command == "exit" {
			done <- true
			return
		}
		commands <- command

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