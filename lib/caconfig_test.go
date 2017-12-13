package lib

import (
	"testing"
)

func BenchmarkGetCACert(b *testing.B) {
	ca := &CA{}
	for i := 0; i < b.N; i++ {
		_, err := ca.getCACert()
		if err != nil {
			panic("getCACert Error!")
		}
	}
}
