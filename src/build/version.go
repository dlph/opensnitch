package build

// version - set by build
var version string

func Version() string {
	if version == "" {
		version = "test"
	}
	return version
}
