package main

import (
	"fmt"
	"log"

	"./serverGo"
)

func main() {
	serverGo.HandleFunc("/", hello)
	err := serverGo.ListenAndServe(":9090", nil)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}

func hello(w serverGo.ResponseWriter, r *serverGo.Request) {
	fmt.Fprintf(w, "Hello, World!")
}
