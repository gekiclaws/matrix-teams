package connector

import (
	"context"
	"strings"
	"testing"
)

func TestWebviewLoginCapturesMSALEncryptionCookie(t *testing.T) {
	login := &WebviewLocalStorageLogin{}
	step, err := login.Start(context.Background())
	if err != nil {
		t.Fatalf("start login: %v", err)
	}
	if step.CookiesParams == nil {
		t.Fatal("expected cookie login parameters")
	}
	script := step.CookiesParams.ExtractJS
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
}
