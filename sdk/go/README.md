# safecadence-go

Official Go SDK for the SafeCadence NetRisk REST API.

## Install

```
go get github.com/famousleads/safecadence-go
```

## Quickstart

```go
package main

import (
    "context"
    "fmt"
    "log"
    "os"

    safecadence "github.com/famousleads/safecadence-go"
)

func main() {
    ctx := context.Background()
    cli := safecadence.NewClient("https://demo.safecadence.com", os.Getenv("SC_API_KEY"))

    hosts, err := cli.ListInventory(ctx)
    if err != nil {
        log.Fatal(err)
    }
    for _, h := range hosts {
        fmt.Println(h.Hostname, h.RiskScore)
    }

    pdf, err := cli.ComposeReport(ctx, safecadence.ComposeOptions{
        Preset: "exec_brief",
        Format: "pdf",
    })
    if err != nil {
        log.Fatal(err)
    }
    os.WriteFile("brief.pdf", pdf, 0o644)
}
```

## Errors

Type-assert with `errors.As`:

```go
var ae *safecadence.AuthError
if errors.As(err, &ae) { /* 401/403 */ }

var rl *safecadence.RateLimitError
if errors.As(err, &rl) { time.Sleep(rl.RetryAfter) }
```

## License

MIT
