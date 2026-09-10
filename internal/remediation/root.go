package remediation

// The order matters since we use numeric comparison to find the most restrictive remediation.
const (
	Allow     Remediation = iota // Allow remediation
	Unknown                      // Unknown remediation (Unknown is used to have a value for remediation we don't support EG "MFA")
	Captcha                      // Captcha remediation
	Challenge                    // Challenge remediation (JS PoW + fingerprint, issued by AppSec)
	Ban                          // Ban remediation
)

type Remediation uint8 // Remediation type is smallest uint to save space

func (r Remediation) String() string {
	switch r {
	case Ban:
		return "ban"
	case Captcha:
		return "captcha"
	case Challenge:
		return "challenge"
	case Unknown:
		return "unknown"
	default:
		return "allow"
	}
}

func FromString(s string) Remediation {
	switch s {
	case "ban":
		return Ban
	case "captcha":
		return Captcha
	case "challenge":
		return Challenge
	case "allow":
		return Allow
	default:
		return Unknown
	}
}
