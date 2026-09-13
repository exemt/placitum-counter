package decide

import (
	"testing"

	"github.com/exemt/placitum-counter/internal/config"
)

func TestFireOverloadThreshold(t *testing.T) {
	at := 60
	rows := []config.Outcome{
		{On: config.OnOverload, At: &at, To: "captcha", Do: "challenge"},
		{On: config.OnOverload, To: "vlai", Do: "skip"},
		{On: config.OnDeny, To: "captcha", Do: "challenge"},
	}

	if got := FireOverload(rows, 59, false, "203.0.113.7", "X_QUEUE_LIMIT"); len(got.Actions) != 0 {
		t.Fatalf("below the threshold: %d asks", len(got.Actions))
	}

	// От порога -- только строка с порогом: без порога это край.
	if got := FireOverload(rows, 60, false, "203.0.113.7", "X_QUEUE_LIMIT"); len(got.Actions) != 1 {
		t.Fatalf("at the threshold: %d asks", len(got.Actions))
	}

	// Сброс: обе строки перегрузки, deny молчит.
	if got := FireOverload(rows, 100, true, "203.0.113.7", "X_QUEUE_LIMIT"); len(got.Actions) != 2 {
		t.Fatalf("shed: %d asks", len(got.Actions))
	}
}
