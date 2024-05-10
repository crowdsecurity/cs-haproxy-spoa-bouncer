package remediation

// The order matters since we use slices.Max to get the max value
const (
	Allow   Remediation = iota // Allow remediation
	Unknown                    // Unknown remediation (Unknown is used to have a value for remediation we don't support EG "MFA")
	Captcha                    // Captcha remediation
	Ban                        // Ban remediation
)

type Remediation uint8 // Remediation type is smallest uint to save space

func (r Remediation) String() string {
	switch r {
	case Ban:
		return "ban"
	case Captcha:
		return "captcha"
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
	case "allow":
		return Allow
	default:
		return Unknown
	}
}
