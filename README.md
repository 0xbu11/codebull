# CodeBull Setup

CodeBull is a dynamic instrumentation library for Go applications.

## Requirements

**Important:** This project only supports Go version **1.22.x**. Compilation with Go 1.23 or later is explicitly disabled via build constraints.

Ensure you have Go 1.22.0-1.22.x installed.

## Quick Start

### 1. Installation

Ensure you have Go 1.22.x installed.

```bash
# Clone the repository (if not already done)
git clone git@github.com:0xbu11/codebull.git
cd codebull
```

### 2. Integration

To instrument your application, import the codebull package (using a blank import if you only need the side effects) and ensure your code is compiled with specific flags to preserve debug information.

**In your `main.go`:**

```go
import (
    _ "github.com/0xbu11/codebull" // Triggers auto-start (default port 8888)
)

func main() {
    // ... your application logic ...
}
```

### 3. Compilation

You **must** compile your application with the following flags to enable DWARF location lists:

```bash
go build -dwarflocationlists=true" -o myapp .
```

### 4. Running

Run your application. The Shadow server will automatically start on port **8888** by default.

To change the port for both HTTP and WebSocket, set one of these environment variables before starting your app:

- `EGO_SHADOW_PORT` (port only, e.g. `9000`)
- `EGO_SHADOW_ADDR` (full listen address, e.g. `127.0.0.1:9000` or `:9000`)

`EGO_SHADOW_ADDR` has higher priority than `EGO_SHADOW_PORT`.

```bash
export EGO_SHADOW_PORT=9000
./myapp
```

You can verify it's running:
```bash
curl http://localhost:9000/health
```

### 5. Running the Demo

A demo application is included to showcase the functionality.

```bash
# Build with DWARF preserved (required for variable harvesting)
go build \
    -gcflags=" -dwarflocationlists=true -N -l" \
    -ldflags="-w=0 -s=0 -compressdwarf=false" \
    -o demo_bin ./demo/simple_demo.go

./demo_bin
```

## API Documentation

See [API.md](API.md) for details on the HTTP and WebSocket endpoints for controlling traces and receiving data.

## Requirements

- Go 1.22+
- Linux (for current build scripts and Ptrace usage)
