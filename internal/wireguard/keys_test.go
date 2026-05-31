package wireguard

import "testing"

func TestGenerateKeySetClampsPrivateKey(t *testing.T) {
	for range 100 {
		keySet, err := GenerateKeySet()
		if err != nil {
			t.Fatalf("GenerateKeySet returned error: %v", err)
		}

		if keySet.PrivateKey[0]&7 != 0 {
			t.Fatalf("private key low bits are not clamped: first byte is %#02x", keySet.PrivateKey[0])
		}
		if keySet.PrivateKey[31]&0x80 != 0 {
			t.Fatalf("private key high bit is not clamped: last byte is %#02x", keySet.PrivateKey[31])
		}
		if keySet.PrivateKey[31]&0x40 == 0 {
			t.Fatalf("private key second-highest bit is not clamped: last byte is %#02x", keySet.PrivateKey[31])
		}
	}
}
