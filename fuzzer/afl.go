package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

var fuzzStat fuzzCampaignStatus
var targetPoints map[string]string
var script []string

type fuzzTarget struct {
	TargetPath			string			`json:"target_path"`
	Requests			[]string		`json:"requests"`
	Methods				map[string]int	`json:"methods"`
	IsSoapAction		bool			`json:"is_soapaction"`
	LastCompletedTrial	int				`json:"last_completed_trial"`
	LastCompletedRefuzz	int				`json:"last_completed_refuzz"`
}

type fuzzCampaignStatus struct {
	TrialStart		string			`json:"trial_start"`
	TrialComplete	bool			`json:"trial_complete"`
	Targets			[]fuzzTarget	`json:"targets"`
}

func runAFL(fuzzingPath string, fuzzerNumber int) {
	createDict(fuzzingPath)
	createFuzzStat(fuzzingPath)
	initPoints(fuzzingPath)

	for i := 0; i < len(targetPoints); i++ {
		resetChan = make(chan struct{})
		targetURL := targetPoints[fuzzStat.Targets[i].TargetPath]

		fmt.Println("Current Fuzzing target :", targetURL)

		createScript(fuzzingPath, i)
		createSeed(fuzzingPath, i)
		
		u, _ := url.Parse(fuzzStat.Targets[i].TargetPath)
                os.Setenv("SCRIPT_FILENAME", "/app" + u.Path)
                fmt.Println("SCRIPT_FILENAME" + "/app" + u.Path)

                // cmd := exec.Command("sh", fuzzingPath + "/run.sh")

                var slc = []string{"export", "SCRIPT_FILENAME=" + "/app" + u.Path, "&&"}
                slc = append(slc, script[1:]...)
                fmt.Println(strings.Join(slc," "))
		
                cmd := exec.Command("bash", "-c",  strings.Join(slc," "))
		stdout, _ := cmd.StdoutPipe()
		var outputBuf bytes.Buffer
		
		cmd.Start()
		go io.Copy(&outputBuf, stdout)

		go exitFuzzer(cmd)
		go exitAFL(cmd)
		runTimer(fuzzingPath, configData.Timeout)

		select {
		case <-resetChan:
			output := outputBuf.Bytes()
			os.WriteFile(fuzzingPath + "/output/fuzzer.log", output, 0644)
			finishFuzz(fuzzingPath, i)
			cleanDir(fuzzingPath + "/input", fuzzerNumber)
			cleanDir(fuzzingPath + "/output", fuzzerNumber)
			os.Exit(0)
		default:
			output := outputBuf.Bytes()
			os.WriteFile(fuzzingPath + "/output/fuzzer.log", output, 0644)
			finishFuzz(fuzzingPath, i)
			cleanDir(fuzzingPath + "/input", fuzzerNumber)
			cleanDir(fuzzingPath + "/output", fuzzerNumber)
		}
	}
}

func initDir(i int) string {
	fuzzingDir := fmt.Sprintf("fuzzing-%d", i)
	inputDir := fuzzingDir + "/input"
	seedsDir := inputDir + "/seeds"
	outputDir := fuzzingDir + "/output"

	mkdir(fuzzingDir)
	mkdir(inputDir)
	mkdir(seedsDir)
	mkdir(outputDir)

	return fuzzingDir
}

func copyDir(src string, dst string) error {
	err := os.MkdirAll(dst, os.ModePerm)

	if err != nil {
		return err
	}

	entries, err := os.ReadDir(src)
	
	if err != nil {
		return err
	}

	for _, entry := range entries {
		srcPath := filepath.Join(src, entry.Name())
		dstPath := filepath.Join(dst, entry.Name())

		if entry.IsDir() {
			if err := copyDir(srcPath, dstPath); err != nil {
				return err
			}
		} else {
			srcFile, err := os.Open(srcPath)

			if err != nil {
				return err
			}

			defer srcFile.Close()

			dstFile, err := os.Create(dstPath)

			if err != nil {
				return err
			}

			defer dstFile.Close()

			if _, err := io.Copy(dstFile, srcFile); err != nil {
				return err
			}
		}
	}

	return nil
}

func cleanDir(dir string, i int) {
	entries, err := os.ReadDir(dir)

	if err != nil {
		panic(err)
	}

	for _, entry := range entries {
		if !(entry.Name() == "dict.txt" || entry.Name() == "fuzz_stat.json") {
			filePath := filepath.Join(dir, entry.Name())

			if entry.IsDir() {
				err := os.RemoveAll(filePath)
				if err != nil {
					panic(err)
				}
			} else {
				err := os.Remove(filePath)
				if err != nil {
					panic(err)
				}
			}
		}
	}
}

func mkdir(dirName string) {
	if _, err := os.Stat(dirName); os.IsNotExist(err) {
		err := os.MkdirAll(dirName, os.ModePerm)

		if err != nil {
			panic(err)
		}
	} else if err != nil {
		panic(err)
	} else {
		// fmt.Println("Directory already exists:", dirName)
	}
}

func createScript(fuzzingPath string, i int) {
	scriptPath := fuzzingPath + "/run.sh"
	file, err := os.Create(scriptPath)

	if err != nil {
		panic(err)
	}

	defer file.Close()

	var targets []string
	scriptContent := "#!/bin/sh\n\n"

	for key := range requestData.RequestsFound {
		targets = append(targets, strings.Split(key, " ")[1])
	}

	scriptContent += configData.AFLPath + "afl-fuzz"
	scriptContent += " -i " + fuzzingPath + "/input/seeds/"// + strings.ReplaceAll(strings.Split(targets[i], "//")[1], "/", "+")
	scriptContent += " -o " + fuzzingPath + "/output"
	scriptContent += " -m " + configData.Memory
	scriptContent += " -x " + fuzzingPath + "/input/dict.txt -- "
	scriptContent += configData.TargetBinary
	scriptContent += fuzzStat.Targets[i].TargetPath

	script = strings.Fields(scriptContent)

	_, err = file.WriteString(scriptContent)

	if err != nil {
		panic(err)
	}

	err = os.Chmod(scriptPath, 0755)

	if err != nil {
		panic(err)
	}
}

func createDict(fuzzingPath string) {
	dictPath := fuzzingPath + "/input/dict.txt"
	var dictContent string
	file, err := os.Create(dictPath)

	if err != nil {
		panic(err)
	}

	defer file.Close()

	for i, param := range requestData.InputSet {
		dictContent += fmt.Sprintf("string_%d=\"%v\"\n", i, strings.ReplaceAll(url.QueryEscape(param), "%", "\\x"))
	}

	_, err = file.WriteString(dictContent)

	if err != nil {
		panic(err)
	}
}

func createFuzzStat(fuzzingPath string) {
	uniqCheck := make(map[string]int)
	targetIndex := 0

	fuzzStat.TrialStart = time.Now().Format("2006_01_02_15_04")
	fuzzStat.TrialComplete = false
	fuzzStat.Targets = []fuzzTarget{}

	for key, value := range requestData.RequestsFound {
		targetURL := strings.Split(value.URLString, "?")[0]
		method := strings.Split(key, " ")[0]
		_, exist := uniqCheck[targetURL]

		if exist {
			fuzzStat.Targets[uniqCheck[targetURL]].Requests = append(fuzzStat.Targets[uniqCheck[targetURL]].Requests, key)
			fuzzStat.Targets[uniqCheck[targetURL]].Methods[method]++
		} else {
			uniqCheck[targetURL] = targetIndex
			targetIndex++

			tempFuzzTarget := fuzzTarget{
				Methods: make(map[string]int),
			}

			tempFuzzTarget.TargetPath = strings.Split(value.URLString, "?")[0]
			tempFuzzTarget.Requests = append(tempFuzzTarget.Requests, key)
			tempFuzzTarget.Methods[method] = 1

			fuzzStat.Targets = append(fuzzStat.Targets, tempFuzzTarget)
		}
	}

	data, err := json.MarshalIndent(fuzzStat, "", "	")
	data = []byte(strings.ReplaceAll(string(data), "\\u0026", "&"))

	if err != nil {
		panic(err)
	}

	file, err := os.Create(fuzzingPath + "/output/fuzz_stat.json")

	if err != nil {
		panic(err)
	}

	defer file.Close()

	_, err = file.Write(data)

	if err != nil {
		panic(err)
	}
}

func initPoints(fuzzingPath string) {
	targetPoints = make(map[string]string)

	for i := 0; i < len(fuzzStat.Targets); i++ {
		targetPoint := strings.ReplaceAll(strings.Split(fuzzStat.Targets[i].TargetPath, "//")[1], "/", "+")
		targetPoints[fuzzStat.Targets[i].TargetPath] = targetPoint
	}
}

func createSeed(fuzzingPath string, i int) {
	var seed string

	dir := fuzzingPath + "/input/seeds"

	for j := 0; j < len(fuzzStat.Targets[i].Requests); j++ {
		req := fuzzStat.Targets[i].Requests[j]
		var getQuery string
		var postData string
		var headers string

		if strings.Split(req, " ")[0] == "GET" {
			if strings.Contains(req, "?") {
				getQuery = strings.Split(strings.Split(req, "?")[1], " ")[0]
			}
		} else if strings.Split(req, " ")[0] == "POST" {
			postData = requestData.RequestsFound[req].PostData
		}

		for key, value := range requestData.RequestsFound[req].Headers {
			headers += fmt.Sprintf("%v:%v\n", key, value)
		}

		mkdir(dir)

		seed = fmt.Sprintf("\x00%v\x00%v\x00%v", getQuery, postData, headers)

		file, err := os.Create(dir + fmt.Sprintf("/seed-%d", j))

		if err != nil {
			panic(err)
		}

		defer file.Close()
		
		_, err = file.Write([]byte(seed))

		if err != nil {
			panic(err)
		}
	}
}

func finishFuzz(fuzzingPath string, i int) {
	resultDir := fuzzingPath + "/../results/" + targetPoints[fuzzStat.Targets[i].TargetPath]

	err := copyDir(fuzzingPath, resultDir)

	if err != nil {
		panic(err)
	}

	mkdir(resultDir)
}
