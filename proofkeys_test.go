package pythia

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewProofKeys(t *testing.T) {
	keys, err := NewProofKeys("5.dddd", "1.aaaa", "2.bbbb", "4.xxxx")
	assert.NoError(t, err)

	current, err := keys.GetCurrent()

	assert.NoError(t, err)

	assert.Equal(t, uint(5), current.Version)
}
