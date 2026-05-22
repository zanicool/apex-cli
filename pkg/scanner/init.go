package scanner

import "os"

func init() {
	osLookupEnv = os.LookupEnv
}
