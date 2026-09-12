/*
 * Форма провода -- контракт с модулем, и расхождение с ней должно падать здесь,
 * а не на живом трафике. Проверяется то, что инспектор вправе ожидать от
 * сообщения фазы ответа: обе стороны в одном сообщении, фаза у чужого вердикта,
 * продолжение.
 */

package protocol

import (
	"testing"
)

const responseMessage = `{
  "v": 2,
  "rid": "3f2a9c1e00000017",
  "ray": "11d4ea9c-0000-4000-8000-000000000000",
  "phase": "response",
  "wave": 0,
  "inspector": "json",
  "deadline_ms": 800,
  "audit_subject": "waf.audit.inspector.json",
  "node": "edge-07",
  "conn": { "client_ip": "203.0.113.42", "client_port": 51544 },
  "http": {
    "method": "POST", "scheme": "https", "host": "shop.example.com",
    "uri": "/api/orders", "args_size": 8, "version": "HTTP/2.0"
  },
  "needs": ["headers", "body"],
  "response": { "status": 500, "upstream_ms": 34 },
  "store": {
    "headers": { "store": "hot", "driver": "redis",
                 "key": "w7:3f2a9c1e00000017:rsp:hdr", "size": 318 },
    "args": null,
    "body": { "store": "hot", "driver": "redis",
              "key": "w7:3f2a9c1e00000017:rsp", "size": 48211, "complete": true }
  },
  "request_store": {
    "headers": { "store": "hot", "driver": "redis",
                 "key": "w7:3f2a9c1e00000017:req:hdr", "size": 412 },
    "args": { "store": "hot", "driver": "redis",
              "key": "w7:3f2a9c1e00000017:req:arg", "size": 8 },
    "body": null
  },
  "resume": { "token": "7f3a91", "require": true },
  "route": { "server_name": "shop.example.com", "location": "/api",
             "profile": "strict" },
  "score": { "total": 0, "deny_at": 80 },
  "prior": [
    { "phase": "request", "inspector": "json", "verdict": "score",
      "score": 75 },
    { "phase": "response", "inspector": "dlp", "verdict": "allow" }
  ]
}`

func TestParseResponsePhase(t *testing.T) {
	req, err := Parse([]byte(responseMessage))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if req.Phase != PhaseResponse {
		t.Fatalf("phase = %q", req.Phase)
	}

	if req.Response == nil || req.Response.Status != 500 {
		t.Fatalf("response section = %+v", req.Response)
	}

	// store -- объекты текущей фазы: заголовки и тело ответа.
	if !req.Store.Headers.Placed() || !req.Store.Body.Placed() {
		t.Fatalf("response objects are not placed: %+v", req.Store)
	}

	if req.Store.Args != nil {
		t.Errorf("response phase must not carry args: %+v", req.Store.Args)
	}

	// request_store -- контекст запроса, из которого восстанавливается
	// транзакция.
	if !req.RequestStore.Headers.Placed() || !req.RequestStore.Args.Placed() {
		t.Fatalf("request context is missing: %+v", req.RequestStore)
	}

	if req.RequestStore.Body != nil {
		t.Errorf("request body was not sent, want nil: %+v", req.RequestStore.Body)
	}

	if req.RequestStore.Headers.Key == req.Store.Headers.Key {
		t.Error("request and response headers must be different objects")
	}

	if req.Resume == nil || req.Resume.Token != "7f3a91" {
		t.Fatalf("resume = %+v", req.Resume)
	}

	// require -- решение маршрута на случай, если состояния под ключом нет:
	// без него переигрываем, с ним отказываем. Едет на любой subject.
	if !req.Resume.Require {
		t.Errorf("resume.require = false, want true")
	}

	if req.Resume.Want {
		t.Errorf("resume.want on response phase = true, want false")
	}

	if len(req.Prior) != 2 {
		t.Fatalf("prior = %+v", req.Prior)
	}

	if req.Prior[0].Phase != PhaseRequest || req.Prior[0].Score != 75 {
		t.Errorf("prior[0] = %+v, want the request phase verdict", req.Prior[0])
	}

	if req.Prior[1].Phase != PhaseResponse {
		t.Errorf("prior[1] = %+v, want a verdict of this phase", req.Prior[1])
	}
}

// Старый модуль фазы в prior не пишет. Это не ошибка разбора: пустая фаза
// означает "не знаем", и инспектор обязан отличать её от "фаза запроса".
func TestParsePriorWithoutPhase(t *testing.T) {
	msg := `{"v":2,"rid":"01","phase":"request","inspector":"json",
	         "http":{"method":"GET","uri":"/"},
	         "prior":[{"inspector":"ip","verdict":"allow"}]}`

	req, err := Parse([]byte(msg))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if req.Prior[0].Phase != "" {
		t.Errorf("phase = %q, want the empty string", req.Prior[0].Phase)
	}
}

func TestParseRejectsMixedRequestStoreLocator(t *testing.T) {
	msg := `{"v":2,"rid":"01","phase":"response","inspector":"json",
	         "http":{"method":"GET","uri":"/"},
	         "request_store":{"headers":{"store":"hot","driver":"redis"}}}`

	if _, err := Parse([]byte(msg)); err == nil {
		t.Fatal("a locator with a driver and no key was accepted")
	}
}

func TestParseRejectsUnavailableWithAddressInRequestStore(t *testing.T) {
	msg := `{"v":2,"rid":"01","phase":"response","inspector":"json",
	         "http":{"method":"GET","uri":"/"},
	         "request_store":{"body":{"unavailable":"store_error",
	                                  "driver":"redis","key":"k"}}}`

	if _, err := Parse([]byte(msg)); err == nil {
		t.Fatal("a locator mixing unavailable with an address was accepted")
	}
}

// Сообщение фазы запроса не изменилось: request_store в нём просто нет, и
// разбор обязан оставаться прежним.
func TestParseRequestPhaseHasNoRequestStore(t *testing.T) {
	msg := `{"v":2,"rid":"01","phase":"request","inspector":"json",
	         "http":{"method":"GET","uri":"/"},
	         "store":{"headers":{"store":"hot","driver":"redis","key":"k"}}}`

	req, err := Parse([]byte(msg))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if req.RequestStore.Headers != nil || req.RequestStore.Body != nil {
		t.Errorf("request_store = %+v, want empty", req.RequestStore)
	}

	if req.Resume != nil {
		t.Errorf("resume = %+v, want nil", req.Resume)
	}
}
