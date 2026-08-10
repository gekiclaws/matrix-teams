package connector

import (
	"context"
	"strings"
	"testing"
)

func TestWebviewLoginCapturesMSALEncryptionCookie(t *testing.T) {
	script := webviewLoginScript(t)
	for _, expected := range []string{
		"msal.cache.encryption=",
		"__mautrix_teams_msal_cache_encryption",
		`!key.startsWith("__mautrix_teams_")`,
		".Discover.SKYPE-TOKEN",
		".ExportedEncryptionKey.ExportedEncryptionKey",
	} {
		if !strings.Contains(script, expected) {
			t.Fatalf("extraction script is missing %q", expected)
		}
	}
	if strings.Contains(script, `await new Promise`) {
		t.Fatal("extraction script must not block Beeper from registering navigation listeners")
	}
}

func TestWebviewLoginSuppressesPasskeysAndSelectsPasswordFallback(t *testing.T) {
	script := webviewLoginScript(t)
	for _, expected := range []string{
		`Object.defineProperty(Navigator.prototype, "credentials"`,
		`get: async () =>`,
		`throw new DOMException("User cancelled", "NotAllowedError")`,
		`"NotAllowedError"`,
		`webauthn_override=ok`,
		`mautrix-teams WebAuthn blocker installed`,
		`function forceNonPasskeyAuth()`,
		`#idA_PWD_SwitchToPassword`,
		`#idA_PWD_SwitchToCredPicker`,
		`#idBtn_Back`,
		`signing in with your passkey`,
		`cancel_passkey`,
		`other ways to sign in`,
		`auth_fallback_click=`,
		`forceNonPasskeyAuth();`,
	} {
		if !strings.Contains(script, expected) {
			t.Fatalf("passkey suppression script is missing %q", expected)
		}
	}
}

func TestWebviewLoginReturnsBeforeRegisteringNavigationWatcher(t *testing.T) {
	script := webviewLoginScript(t)
	for _, expected := range []string{
		`globalThis.__mautrixTeamsLoginPoller = setInterval`,
		`globalThis.__BEEP_BEEP_AUTH_RESULTS__ = result`,
		`return {};`,
		`background_poller=started`,
	} {
		if !strings.Contains(script, expected) {
			t.Fatalf("non-blocking extraction script is missing %q", expected)
		}
	}
}

func webviewLoginScript(t *testing.T) string {
	t.Helper()
	login := &WebviewLocalStorageLogin{}
	step, err := login.Start(context.Background())
	if err != nil {
		t.Fatalf("start login: %v", err)
	}
	if step.CookiesParams == nil {
		t.Fatal("expected cookie login parameters")
	}
	return step.CookiesParams.ExtractJS
}
