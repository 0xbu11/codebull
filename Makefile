.PHONY: demo


demo: 
	rm -f simple_demo_bin
	go build -a -o simple_demo_bin \
		-gcflags=" -dwarflocationlists=true -N -l" \
		-ldflags="-w=0 -s=0 -compressdwarf=false" \
		./demo/simple_demo.go
	./simple_demo_bin
