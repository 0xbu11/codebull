.PHONY: demo

demo: 
	go build -o demo_bin -gcflags="-dwarflocationlists=true" demo/demo.go
	./demo_bin
