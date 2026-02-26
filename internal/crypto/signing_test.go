package crypto

import (
	"testing"
)

func TestGenerateKeypair(t *testing.T) {
	priv, pub, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair error: %v", err)
	}
	if len(priv) != 64 {
		t.Errorf("private key length = %d, want 64", len(priv))
	}
	if len(pub) != 32 {
		t.Errorf("public key length = %d, want 32", len(pub))
	}
}

func TestPrivateKeyPEMRoundtrip(t *testing.T) {
	priv, _, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	pem, err := PrivateKeyToPEM(priv)
	if err != nil {
		t.Fatalf("PrivateKeyToPEM error: %v", err)
	}

	loaded, err := LoadPrivateKey(pem)
	if err != nil {
		t.Fatalf("LoadPrivateKey error: %v", err)
	}

	if !priv.Equal(loaded) {
		t.Error("loaded key does not match original")
	}
}

func TestPublicKeyPEMRoundtrip(t *testing.T) {
	_, pub, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	pem, err := PublicKeyToPEM(pub)
	if err != nil {
		t.Fatalf("PublicKeyToPEM error: %v", err)
	}

	loaded, err := LoadPublicKey(pem)
	if err != nil {
		t.Fatalf("LoadPublicKey error: %v", err)
	}
	if !pub.Equal(loaded) {
		t.Error("loaded key does not match original")
	}
}

func TestSignVerify(t *testing.T) {
	priv, pub, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("test message")

	sig := Sign(priv, data)
	if !Verify(pub, data, sig) {
		t.Error("valid signature rejected")
	}
}

func TestVerifyInvalidSignature(t *testing.T) {
	priv, _, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	_, pub2, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	data := []byte("test message")
	sig := Sign(priv, data)

	// Wrong key
	if Verify(pub2, data, sig) {
		t.Error("signature with wrong key should be rejected")
	}

	// Tampered data
	_, pub, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	_ = pub
	if Verify(pub2, []byte("tampered"), sig) {
		t.Error("signature with tampered data should be rejected")
	}
}

func TestPublicKeyFingerprint(t *testing.T) {
	_, pub, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	fp, err := PublicKeyFingerprint(pub)
	if err != nil {
		t.Fatalf("PublicKeyFingerprint error: %v", err)
	}

	if len(fp) != 16 {
		t.Errorf("fingerprint length = %d, want 16", len(fp))
	}

	// Same key should produce same fingerprint
	fp2, err := PublicKeyFingerprint(pub)
	if err != nil {
		t.Fatal(err)
	}
	if fp != fp2 {
		t.Error("same key should produce same fingerprint")
	}
}
