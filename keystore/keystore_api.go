package keystore

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/veles-security/vcrypt/key"
)

// SignResult contains the signature and the exact key selection made by the
// service.
type SignResult struct {
	Signature []byte
	Key       key.KeyDescriptor
}

// Sign selects an active key that supports one of the requested algorithms and
// signs message with it.
func (k *store) Sign(ctx context.Context, message []byte, options ...SignOption) (SignResult, error) {
	var request operationQuery
	for _, option := range k.runtimeOptions {
		option(&request)
	}
	for _, option := range options {
		option(&request)
	}

	if len(request.Algorithms) == 0 {
		return SignResult{}, fmt.Errorf("keystore: signing algorithms are empty")
	}

	selected, algorithm, err := k.selectKey(ctx, key.KeyOpSign, request.Keys, request.Algorithms)
	if err != nil {
		return SignResult{}, err
	}

	signer, ok := selected.Backend().(key.Signer)
	if !ok {
		return SignResult{}, fmt.Errorf("keystore: backend for key %q does not implement signing", selected.ID())
	}
	signature, err := signer.Sign(ctx, algorithm, message)
	if err != nil {
		return SignResult{}, fmt.Errorf("keystore: sign with key %q and algorithm %q: %w", selected.ID(), algorithm, err)
	}

	return SignResult{
		Signature: signature,
		Key:       selected.Descriptor(algorithm),
	}, nil
}

// VerifySignature selects a key and verifies signature. Active and passive
// keys are eligible for verification.
func (k *store) VerifySignature(ctx context.Context, message, signature []byte, options ...VerifyOption) error {
	var request operationQuery
	for _, option := range k.runtimeOptions {
		option(&request)
	}
	for _, option := range options {
		option(&request)
	}

	if len(request.Algorithms) == 0 {
		return fmt.Errorf("keystore: verification algorithm is empty")
	}

	selected, algorithm, err := k.selectKey(
		ctx,
		key.KeyOpVerify,
		request.Keys,
		request.Algorithms,
	)
	if err != nil {
		return err
	}

	verifier, ok := selected.Backend().(key.SignatureVerifier)
	if !ok {
		return fmt.Errorf("keystore: backend for key %q does not implement signature verification", selected.ID())
	}
	if err := verifier.VerifySignature(ctx, algorithm, signature, message); err != nil {
		return fmt.Errorf("keystore: verify with key %q and algorithm %q: %w", selected.ID(), algorithm, err)
	}
	return nil
}

// EncryptResult contains the ciphertext and the exact key selection made by
// the service.
type EncryptResult struct {
	Ciphertext []byte
	Key        key.KeyDescriptor
}

// Encrypt selects an active key that supports one of the requested algorithms
// and encrypts plaintext with it.
func (k *store) Encrypt(ctx context.Context, plaintext []byte, options ...EncryptOption) (EncryptResult, error) {
	var request operationQuery
	for _, option := range k.runtimeOptions {
		option(&request)
	}
	for _, option := range options {
		option(&request)
	}

	if len(request.Algorithms) == 0 {
		return EncryptResult{}, fmt.Errorf("keystore: encryption algorithms are empty")
	}

	selected, algorithm, err := k.selectKey(ctx, key.KeyOpEncrypt, request.Keys, request.Algorithms)
	if err != nil {
		return EncryptResult{}, err
	}
	encrypter, ok := selected.Backend().(key.Encrypter)
	if !ok {
		return EncryptResult{}, fmt.Errorf("keystore: backend for key %q does not implement encryption", selected.ID())
	}
	ciphertext, err := encrypter.Encrypt(ctx, algorithm, plaintext)
	if err != nil {
		return EncryptResult{}, fmt.Errorf("keystore: encrypt with key %q and algorithm %q: %w", selected.ID(), algorithm, err)
	}
	return EncryptResult{Ciphertext: ciphertext, Key: selected.Descriptor(algorithm)}, nil
}

// Decrypt selects an active or passive key and decrypts ciphertext with it.
func (k *store) Decrypt(ctx context.Context, ciphertext []byte, options ...DecryptOption) ([]byte, error) {
	var request operationQuery
	for _, option := range k.runtimeOptions {
		option(&request)
	}
	for _, option := range options {
		option(&request)
	}

	if len(request.Algorithms) == 0 {
		return nil, fmt.Errorf("keystore: decryption algorithms are empty")
	}

	selected, algorithm, err := k.selectKey(ctx, key.KeyOpDecrypt, request.Keys, request.Algorithms)
	if err != nil {
		return nil, err
	}
	decrypter, ok := selected.Backend().(key.Decrypter)
	if !ok {
		return nil, fmt.Errorf("keystore: backend for key %q does not implement decryption", selected.ID())
	}
	plaintext, err := decrypter.Decrypt(ctx, algorithm, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("keystore: decrypt with key %q and algorithm %q: %w", selected.ID(), algorithm, err)
	}
	return plaintext, nil
}

func (k *store) selectKey(
	ctx context.Context,
	operation key.KeyOperation,
	selector KeySelector,
	algorithms []key.KeyAlg,
) (key.Key, key.KeyAlg, error) {
	if k == nil {
		return key.Key{}, "", fmt.Errorf("keystore: not initialized")
	}

	candidates, err := k.repository.Find(ctx, selector)
	if err != nil {
		return key.Key{}, "", fmt.Errorf("keystore: find key: %w", err)
	}

	// Keep repository order deterministic for equal-priority candidates so a
	// tie can be detected rather than resolved by source load order.
	sort.SliceStable(candidates, func(i, j int) bool {
		return candidates[i].Priority() > candidates[j].Priority()
	})

	now := time.Now()
	for _, algorithm := range algorithms {
		var matches []key.Key
		for _, candidate := range candidates {
			if k.eligible(candidate, operation, algorithm, now) {
				matches = append(matches, candidate)
			}
		}
		if len(matches) == 0 {
			continue
		}
		if len(matches) > 1 && matches[0].Priority() == matches[1].Priority() {
			return key.Key{}, "", fmt.Errorf("keystore: multiple keys with priority %d support operation %q and algorithm %q", matches[0].Priority(), operation, algorithm)
		}
		return matches[0], algorithm, nil
	}

	return key.Key{}, "", fmt.Errorf("keystore: no eligible key supports operation %q and algorithms %v", operation, algorithms)
}

func (k *store) eligible(candidate key.Key, operation key.KeyOperation, algorithm key.KeyAlg, now time.Time) bool {
	if candidate.Backend() == nil {
		return false
	}
	if operation == key.KeyOpSign || operation == key.KeyOpEncrypt {
		if candidate.Status() != key.KeyStatusActive {
			return false
		}
	} else if candidate.Status() != key.KeyStatusActive && candidate.Status() != key.KeyStatusPassive {
		return false
	}
	if !candidate.NotBefore().IsZero() && now.Before(candidate.NotBefore()) {
		return false
	}
	if !candidate.NotAfter().IsZero() && now.After(candidate.NotAfter()) {
		return false
	}
	use := useForOperation(operation)
	if !candidate.Backend().Supports(use, operation, algorithm) {
		return false
	}

	restrictions := candidate.Restrictions()
	if len(restrictions) == 0 {
		return true
	}
	for _, restriction := range restrictions {
		if restriction.Use == use && restriction.Operation == operation && restriction.Algorithm == algorithm {
			return true
		}
	}
	return false
}

func useForOperation(operation key.KeyOperation) key.KeyUse {
	if operation == key.KeyOpEncrypt || operation == key.KeyOpDecrypt {
		return key.KeyUseEncryption
	}
	return key.KeyUseSigning
}
