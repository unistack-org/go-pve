package pve

import (
	"context"
	"fmt"
	"log"
	"strings"
)

// logKV writes a structured line to the standard library logger:
//
//	"<msg> key1=val1 key2=val2"
//
// It exists so the engine keeps a single logging dependency (the stdlib
// log package) and stays embeddable outside unistack.
func logKV(ctx context.Context, level, msg string, kv ...any) {
	var b strings.Builder
	b.WriteString("pve: ")
	b.WriteString(msg)
	for i := 0; i+1 < len(kv); i += 2 {
		fmt.Fprintf(&b, " %v=%v", kv[i], kv[i+1])
	}
	line := b.String()
	if ctx != nil {
		line = level + " " + line
	}
	switch level {
	case "warn":
		log.Printf("[WARN] %s", line)
	default:
		log.Printf("[INFO] %s", line)
	}
}
