package connector

import (
	"context"
	"errors"
	"net/http"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/database"
	"maunium.net/go/mautrix/bridgev2/networkid"
)

const (
	FlowIDWebviewLocalStorage = "webview_localstorage"

	LoginStepIDWebviewLocalStorage = "go.mau.teams.webview_localstorage"

	teamsLoginSpecialStorage = "go.mau.teams.storage"
	teamsLoginSpecialDebug   = "go.mau.teams.debug"
)

var loginFlowWebviewLocalStorage = bridgev2.LoginFlow{
	Name:        "teams.live.com (in-app browser)",
	Description: "Login using an embedded browser and automatic localStorage extraction.",
	ID:          FlowIDWebviewLocalStorage,
}

type WebviewLocalStorageLogin struct {
	Main      *TeamsConnector
	User      *bridgev2.User
	submitted atomic.Bool
	canceled  atomic.Bool
}

var _ bridgev2.LoginProcessCookies = (*WebviewLocalStorageLogin)(nil)

func (l *WebviewLocalStorageLogin) Start(ctx context.Context) (*bridgev2.LoginStep, error) {
	_ = ctx
	fullStorageKey := "__mautrix_teams_full_storage"
	if l != nil && l.User != nil {
		l.User.Log.Info().
			Str("local_storage_key", fullStorageKey).
			Msg("Starting Teams webview login flow with auto localStorage extraction")
		go func() {
			ticker := time.NewTicker(15 * time.Second)
			defer ticker.Stop()
			for i := 1; i <= 8; i++ { // up to ~2 minutes
				<-ticker.C
				if l.submitted.Load() || l.canceled.Load() {
					return
				}
				l.User.Log.Warn().
					Int("elapsed_seconds", i*15).
					Msg("Teams webview login still waiting for cookie submission")
			}
			if !l.submitted.Load() && !l.canceled.Load() {
				l.User.Log.Warn().Msg("Teams webview login has not submitted cookies after 2 minutes; extraction may be stalled")
			}
		}()
	}
	instructions := "Log in to Teams in the embedded browser. The bridge will automatically extract localStorage, close the window, and return you to Beeper."
	return &bridgev2.LoginStep{
		Type:         bridgev2.LoginStepTypeCookies,
		StepID:       LoginStepIDWebviewLocalStorage,
		Instructions: instructions,
		CookiesParams: &bridgev2.LoginCookiesParams{
			URL: "https://teams.live.com/v2",
			Fields: []bridgev2.LoginCookieField{
				{
					ID:       "storage",
					Required: true,
					Sources: []bridgev2.LoginCookieFieldSource{
						{
							// Primary path: direct ExtractJS output.
							Type: bridgev2.LoginCookieTypeSpecial,
							Name: teamsLoginSpecialStorage,
						},
						{
							// Fallback path: value persisted by ExtractJS.
							Type: bridgev2.LoginCookieTypeLocalStorage,
							Name: fullStorageKey,
						},
					},
				},
				{
					ID:       "debug",
					Required: false,
					Sources: []bridgev2.LoginCookieFieldSource{
						{
							Type: bridgev2.LoginCookieTypeSpecial,
							Name: teamsLoginSpecialDebug,
						},
						{
							Type: bridgev2.LoginCookieTypeLocalStorage,
							Name: "__mautrix_teams_debug",
						},
					},
				},
			},
			WaitForURLPattern: ".*",
			ExtractJS: `(async () => {
  const trace = [];
  const addTrace = (msg) => {
    if (trace.length < 80) {
      trace.push(msg);
    }
  };
  const traceValue = () => trace.join(" | ");
  addTrace("start url=" + location.href);

  // The Beeper webview can't display passkey/WebAuthn prompts. Preserve the
  // original workaround exactly: a non-configurable prototype getter that
  // exposes only a rejecting get(). Microsoft then falls back to password/OTP.
  // Keeping this descriptor non-configurable prevents page scripts from
  // restoring the native CredentialContainer after the extractor is injected.
  if (globalThis.__mautrixTeamsWebAuthnBlocked) {
    addTrace("webauthn_override=already_installed");
  } else {
    try {
      Object.defineProperty(Navigator.prototype, "credentials", {
        get() {
          return {
            get: async () => {
              throw new DOMException("User cancelled", "NotAllowedError");
            }
          };
        }
      });
      globalThis.__mautrixTeamsWebAuthnBlocked = true;
      addTrace("webauthn_override=ok");
      console.log("[BrowserAuth] mautrix-teams WebAuthn blocker installed url=" + location.href);
    } catch (e) {
      addTrace("webauthn_override=failed:" + String((e && e.message) || e));
      console.log("[BrowserAuth] mautrix-teams WebAuthn blocker failed url=" + location.href);
    }
  }

  const clickedFallbackControls = new WeakSet();
  function elementLabel(element) {
    return String(
      element?.innerText ||
      element?.textContent ||
      element?.getAttribute?.("aria-label") ||
      element?.getAttribute?.("title") ||
      element?.value ||
      ""
    ).replace(/\s+/g, " ").trim();
  }
  function isVisibleControl(element) {
    if (!element || element.disabled || clickedFallbackControls.has(element)) return false;
    try {
      const style = getComputedStyle(element);
      return style.display !== "none" && style.visibility !== "hidden" && element.getClientRects().length > 0;
    } catch (e) {
      return false;
    }
  }
  function clickFallbackControl(element, reason) {
    if (!isVisibleControl(element)) return false;
    clickedFallbackControls.add(element);
    addTrace("auth_fallback_click=" + reason + ":" + elementLabel(element).slice(0, 80));
    element.click();
    return true;
  }
  function firstVisible(selectors) {
    for (const selector of selectors) {
      let elements = [];
      try { elements = document.querySelectorAll(selector); } catch (e) { continue; }
      for (const element of elements) {
        if (isVisibleControl(element)) return element;
      }
    }
    return null;
  }
  function findControlByText(pattern) {
    for (const element of document.querySelectorAll('button, a, [role="button"], input[type="button"], input[type="submit"]')) {
      if (isVisibleControl(element) && pattern.test(elementLabel(element))) return element;
    }
    return null;
  }
  function forceNonPasskeyAuth() {
    if (!/(^|\.)(live\.com|microsoftonline\.com)$/i.test(location.hostname)) return;

    const passwordControl = firstVisible([
      "#idA_PWD_SwitchToPassword",
      '[data-bind*="SwitchToPassword"]',
      'button[data-testid*="password" i]',
      'a[data-testid*="password" i]',
      '[role="button"][data-testid*="password" i]',
      '[role="button"][data-value="Password" i]'
    ]) || findControlByText(/^(?:use (?:(?:your|my) )?password(?: instead)?|sign in with (?:your )?password|password)[.!…]?$/i);
    if (passwordControl && clickFallbackControl(passwordControl, "password")) return;

    const pageText = String(document.body?.innerText || document.body?.textContent || "");
    if (!/(?:passkey|security key|windows hello|face, fingerprint|scan (?:the |a )?qr)/i.test(pageText)) return;

    const otherWaysControl = firstVisible([
      "#idA_PWD_SwitchToCredPicker",
      "#signInAnotherWay",
      '[data-bind*="SwitchToCredPicker"]',
      '[data-testid*="another-way" i]',
      '[data-testid*="signin-options" i]'
    ]) || findControlByText(/^(?:other ways to sign in|sign-in options|(?:use|choose) another (?:way|method)(?: to sign in)?|more choices|i (?:can't|cannot) use my passkey)[.!…]?$/i);
    if (otherWaysControl && clickFallbackControl(otherWaysControl, "other_ways")) return;

    // Once Microsoft reaches the active passkey verification screen, the only
    // available escape hatch is the back arrow. Cancel that screen first; the
    // next polling iteration can then choose password or another OTP method.
    if (/(?:signing in with your passkey|opening a security window|verifying)/i.test(pageText)) {
      const backControl = firstVisible([
        "#idBtn_Back",
        'button[aria-label="Back" i]',
        '[role="button"][aria-label="Back" i]',
        'button[title="Back" i]',
        '[role="button"][title="Back" i]',
        'button[data-testid*="back" i]',
        '[role="button"][data-testid*="back" i]',
        ".backButton"
      ]) || findControlByText(/^(?:back|go back|previous)[.!…]?$/i);
      clickFallbackControl(backControl, "cancel_passkey");
    }
  }

  function dump() {
    try {
      const storage = Object.fromEntries(
        Object.entries(localStorage).filter(([key]) => !key.startsWith("__mautrix_teams_"))
      );
      const cookiePrefix = "msal.cache.encryption=";
      const encryptionCookie = document.cookie.split(";").map(value => value.trim()).find(value => value.startsWith(cookiePrefix));
      if (encryptionCookie) {
        const cookieValue = encryptionCookie.slice(cookiePrefix.length);
        try {
          storage["__mautrix_teams_msal_cache_encryption"] = decodeURIComponent(cookieValue);
        } catch (e) {
          storage["__mautrix_teams_msal_cache_encryption"] = cookieValue;
        }
      }
      return JSON.stringify(storage);
    } catch (e) { return ""; }
  }
  function trySet(key, value) {
    try { localStorage.setItem(key, value); return true; } catch (e) { return false; }
  }
  function findAuthCacheKey() {
    try {
      let teamsTokenKey = "";
      let teamsEncryptionKeyFound = false;
      for (let i = 0; i < localStorage.length; i++) {
        const k = localStorage.key(i);
        if (!k) continue;
        if (k.startsWith("msal.token.keys.")) return k;
        if (k.startsWith("msal.") && k.includes(".token.keys.")) return k;
        if (k.startsWith("tmp.auth.v1.") && k.endsWith(".Discover.SKYPE-TOKEN")) teamsTokenKey = k;
        if (k.endsWith(".ExportedEncryptionKey.ExportedEncryptionKey")) teamsEncryptionKeyFound = true;
      }
      return teamsTokenKey && teamsEncryptionKeyFound ? teamsTokenKey : "";
    } catch (e) {
      addTrace("auth_cache_scan=failed:" + String((e && e.message) || e));
      return "";
    }
  }
  function captureAuthResult() {
    forceNonPasskeyAuth();
    const key = findAuthCacheKey();
    if (!key) return null;

    addTrace("auth_cache_key_found=" + key);
    const storage = dump();
    addTrace("dump_len=" + storage.length);
    if (!storage) {
      addTrace("dump_empty");
      return null;
    }

    const debug = traceValue();
    const storageSaved = trySet("__mautrix_teams_full_storage", storage);
    const debugSaved = trySet("__mautrix_teams_debug", debug);
    addTrace("stash_storage=" + (storageSaved ? "ok" : "fail") + " stash_debug=" + (debugSaved ? "ok" : "fail"));
    const result = { storage, debug };

    // Beeper reads this global every 100 ms while the browser is open. Publish
    // from the background watcher so ExtractJS itself can return immediately;
    // Beeper otherwise waits for it before registering navigation listeners.
    globalThis.__BEEP_BEEP_AUTH_RESULTS__ = result;
    return result;
  }

  const immediateResult = captureAuthResult();
  if (immediateResult) return immediateResult;

  if (!globalThis.__mautrixTeamsLoginPoller) {
    let pollCount = 0;
    globalThis.__mautrixTeamsLoginPoller = setInterval(() => {
      pollCount++;
      if (pollCount % 50 === 0) {
        let storageLength = -1;
        try { storageLength = localStorage.length; } catch (e) {}
        addTrace("poll i=" + pollCount + " ls_len=" + storageLength + " url=" + location.href);
      }
      const result = captureAuthResult();
      if (result) {
        clearInterval(globalThis.__mautrixTeamsLoginPoller);
        globalThis.__mautrixTeamsLoginPoller = undefined;
      }
    }, 100);
    addTrace("background_poller=started");
  } else {
    addTrace("background_poller=already_started");
  }

  // Returning promptly is required: Beeper attaches runJSOnNavigate only
  // after this promise resolves. The background poller publishes the eventual
  // token result through __BEEP_BEEP_AUTH_RESULTS__.
  return {};
})()`,
		},
	}, nil
}

func (l *WebviewLocalStorageLogin) Cancel() {
	if l != nil {
		l.canceled.Store(true)
		if l.User != nil {
			l.User.Log.Warn().Msg("Teams webview login was canceled before cookie submission")
		}
	}
}

func (l *WebviewLocalStorageLogin) SubmitCookies(ctx context.Context, cookies map[string]string) (*bridgev2.LoginStep, error) {
	if l == nil || l.Main == nil || l.User == nil {
		return nil, errors.New("missing login state")
	}
	l.submitted.Store(true)
	cookieKeys := make([]string, 0, len(cookies))
	for key := range cookies {
		cookieKeys = append(cookieKeys, key)
	}
	sort.Strings(cookieKeys)
	l.User.Log.Info().
		Int("cookie_fields", len(cookies)).
		Strs("cookie_keys", cookieKeys).
		Msg("Teams webview login submitted cookie payload")
	debugInfo := strings.TrimSpace(cookies["debug"])
	if debugInfo != "" {
		l.User.Log.Info().
			Str("teams_login_cookie_debug", truncateForLog(debugInfo, 4000)).
			Msg("Teams login extraction breadcrumbs")
	}
	raw := strings.TrimSpace(cookies["storage"])
	if raw == "" {
		return nil, bridgev2.RespError{ErrCode: "FI.MAU.TEAMS_MISSING_STORAGE", Err: "Missing localStorage payload", StatusCode: http.StatusBadRequest}
	}
	clientID := resolveClientID(l.Main)
	meta, err := ExtractTeamsLoginMetadataFromLocalStorage(ctx, raw, clientID)
	if err != nil {
		return nil, err
	}
	l.User.Log.Info().
		Bool("graph_token_present", strings.TrimSpace(meta.GraphAccessToken) != "").
		Msg("Teams login extracted Graph token state")
	if meta.GraphExpiresAt != 0 {
		l.User.Log.Debug().
			Time("graph_expires_at", time.Unix(meta.GraphExpiresAt, 0).UTC()).
			Msg("Teams login Graph token expiry")
	}
	ul, err := l.User.NewLogin(ctx, &database.UserLogin{
		ID:         networkid.UserLoginID(meta.TeamsUserID),
		RemoteName: meta.TeamsUserID,
		Metadata:   meta,
	}, &bridgev2.NewLoginParams{DeleteOnConflict: true})
	if err != nil {
		return nil, err
	}
	startLoginConnect(ul, loginConnectBaseCtx(l.Main))
	return &bridgev2.LoginStep{
		Type:         bridgev2.LoginStepTypeComplete,
		StepID:       "go.mau.teams.complete",
		Instructions: "Login complete.",
		CompleteParams: &bridgev2.LoginCompleteParams{
			UserLoginID: ul.ID,
			UserLogin:   ul,
		},
	}, nil
}

func loginConnectBaseCtx(main *TeamsConnector) context.Context {
	if main != nil && main.Bridge != nil && main.Bridge.BackgroundCtx != nil {
		return main.Bridge.BackgroundCtx
	}
	return context.Background()
}

func startLoginConnect(login *bridgev2.UserLogin, baseCtx context.Context) {
	if login == nil || login.Client == nil {
		return
	}
	ctx := baseCtx
	if ctx == nil {
		ctx = context.Background()
	}
	ctx = login.Log.WithContext(ctx)
	go login.Client.Connect(ctx)
}

func truncateForLog(value string, maxLen int) string {
	if maxLen <= 0 || len(value) <= maxLen {
		return value
	}
	return value[:maxLen] + "...(truncated)"
}
