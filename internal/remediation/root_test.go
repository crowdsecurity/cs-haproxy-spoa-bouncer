package remediation

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestChallengeString(t *testing.T) {
	assert.Equal(t, "challenge", Challenge.String())
}

func TestFromStringChallenge(t *testing.T) {
	assert.Equal(t, Challenge, FromString("challenge"))
}

func TestFromStringRoundTrip(t *testing.T) {
	for _, r := range []Remediation{Allow, Unknown, Captcha, Challenge, Ban} {
		assert.Equal(t, r, FromString(r.String()), "round-trip failed for %v", r)
	}
}

func TestChallengeOrdering(t *testing.T) {
	// Challenge must be more restrictive than Captcha and less restrictive than Ban
	// so that shouldRunAppSec and the "take the max" logic work correctly.
	assert.Greater(t, Challenge, Captcha)
	assert.Less(t, Challenge, Ban)
	assert.Greater(t, Challenge, Allow)
	assert.Greater(t, Challenge, Unknown)
}
