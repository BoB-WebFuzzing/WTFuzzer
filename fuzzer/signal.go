package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
)

var termChan chan os.Signal
var intChan chan os.Signal
var resetChan chan struct{}
var timerChan chan os.Signal

func exitAFL(c *exec.Cmd) {
	signal.Notify(termChan, syscall.SIGTERM)

	<-termChan

	process := c.Process
	err := process.Signal(syscall.SIGINT)

	if err != nil {
		panic(err)
	}

	fmt.Println("\nSIGTERM received. Exiting...")

	resetChan <- struct{}{}
}

func exitFuzzer(c *exec.Cmd) {
	signal.Notify(intChan, os.Interrupt, syscall.SIGINT)

	<-intChan

	process := c.Process
	err := process.Signal(syscall.SIGINT)

	if err != nil {
		panic(err)
	}

	fmt.Println("\nSIGINT received. Exiting...")

	resetChan <- struct{}{}
}