package pythia

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewProofKeys(t *testing.T) {
	keys, err := NewProofKeys(
		"5.AgwhFXaYR7EWiTxeCCj269+cZKcRiT7x2Ifbyi4HrMnpSCapaoUzoK8rIJSNJC++jA==",
		"1.AgwhFXaYR7EWiTxeCCj269+cZKcRiT7x2Ifbyi4HrMnpSCapaoUzoK8rIJSNJC++jA==",
		"2.AgwhFXaYR7EWiTxeCCj269+cZKcRiT7x2Ifbyi4HrMnpSCapaoUzoK8rIJSNJC++jA==",
		"4.AgwhFXaYR7EWiTxeCCj269+cZKcRiT7x2Ifbyi4HrMnpSCapaoUzoK8rIJSNJC++jA==")
	assert.NoError(t, err)

	current, err := keys.GetCurrent()

	assert.NoError(t, err)

	assert.Equal(t, uint(5), current.Version)

	keys, err = NewProofKeys("5.AgwhFXaYR7")
	assert.Error(t, err)
	assert.Nil(t, keys)
}
