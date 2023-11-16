package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
)

var requestData RequestData

type RequestInfo struct {
	// ID					int						`json:"_id"`
	URLString			string					`json:"url"`
	Method				string					`json:"method"`
	PostData			string					`json:data"`
	Headers				map[string]string		`json:"headers"`
	// ResourceType		string					`json:"_resourceType"`
	// MultipleParamKeys	map[string]interface{}	`json:"multipleParamKeys"`
	// URL					string					`json:"_url"`
	// Attempts			int						`json:"attempts"`
	// Processed			int						`json:"processed"`
	// From				string					`json:"from"`
	// Key					string					`json:"key"`
	// ResponseStatus		int						`json:"response_status"`
	// ResponseContentType	string					`json:"response_content-type"`
}

type InputSet []string

type RequestData struct {
	RequestsFound map[string]RequestInfo `json:"requestsFound"`
	InputSet      InputSet               `json:"inputSet"`
}

func (r *RequestData) parseJSON(fileName string) {
	data, err := os.Open(fileName)

	if err != nil {
		fmt.Println(err)
	}

	defer data.Close()
	
	byteValue, _ := ioutil.ReadAll(data)
	json.Unmarshal(byteValue, &r)
}

func printRequest() {
	fmt.Printf("%-20v\n", "RequestsFound:")

	for key, value := range requestData.RequestsFound {
		fmt.Printf("	%-20v\n", key)
		// fmt.Printf("		%-20v %v\n", "ID:", value.ID)
		fmt.Printf("		%-20v %v\n", "URLString:", value.URLString)
		fmt.Printf("		%-20v %v\n", "Method:", value.Method)
		fmt.Printf("		%-20v %v\n", "PostData:", value.PostData)
		fmt.Printf("		%-20v %v\n", "Headers:", value.Headers)
		// fmt.Printf("		%-20v %v\n", "ResourceType:", value.ResourceType)
		// fmt.Printf("		%-20v %v\n", "MultipleParamKeys:", value.MultipleParamKeys)
		// fmt.Printf("		%-20v %v\n", "URL:", value.URL)
		// fmt.Printf("		%-20v %v\n", "Attempts:", value.Attempts)
		// fmt.Printf("		%-20v %v\n", "Processed:", value.Processed)
		// fmt.Printf("		%-20v %v\n", "From:", value.From)
		// fmt.Printf("		%-20v %v\n", "Key:", value.Key)
		// fmt.Printf("		%-20v %v\n", "ResponseStatus:", value.ResponseStatus)
		// fmt.Printf("		%-20v %v\n", "ResponseContentType:", value.ResponseContentType)
	}

	fmt.Printf("%-20v %v\n", "InputSet:", requestData.InputSet)

}