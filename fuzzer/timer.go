package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func runTimer(fuzzingPath string, timeout int) {
	timerChan := make(chan os.Signal, 1)
	interval := 1 * time.Second
	var crashes int

	signal.Notify(timerChan, syscall.SIGINT, syscall.SIGTERM)

	time.Sleep(interval)

	for i := 0; i < timeout; i++ {
		select {
		case <-timerChan:
			fmt.Println("\nInterrupt signal received. Exiting...")
			return
		default:
			progress := float64(i) / float64(timeout) * 100

			files, err := ioutil.ReadDir(fuzzingPath + "/output/crashes")

			if err != nil {
				panic(err)
			}

			for _, file := range files {
				crashes = 0
				if !file.IsDir() {
					if startsWith(file.Name(), "id:") {
						crashes++
					}
				}
			}
			
			fmt.Print("\033[K")
			fmt.Printf("  [%ds/%ds %.2f%%] completed", i, timeout, progress)
			fmt.Printf(" found total \033[32;5;3m%d crashes\033[0m\r", crashes)

			time.Sleep(interval)
		}
	}

	termChan <- syscall.SIGTERM

	fmt.Printf("  [%ds/%ds %.2f%%] completed\n", timeout, timeout, 100.0)
	fmt.Println("Task completed!")
}

func startsWith(str string, prefix string) bool {
	return len(str) >= len(prefix) && str[:len(prefix)] == prefix
}
