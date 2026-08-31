package keystore

import (
	"context"
	"fmt"
	"sort"
	"sync/atomic"
	"time"

	"github.com/veles-security/vcrypt/key"
)

// Signer selects a signing key and returns its public descriptor together with
// a function that signs one message with that exact key and algorithm.
func (k *store) Signer(ctx context.Context, options ...SignOption) (key.KeyDescriptor, SignFunc, error) {
	var request operationQuery
	for _, option := range k.runtimeOptions {
		option(&request)
	}
	for _, option := range options {
		option(&request)
	}

	if len(request.Algorithms) == 0 {
		return key.KeyDescriptor{}, nil, fmt.Errorf("keystore: signing algorithms are empty")
	}

	selected, algorithm, err := k.selectKey(ctx, key.KeyOpSign, request.Keys, request.Algorithms)
	if err != nil {
		return key.KeyDescriptor{}, nil, err
	}

	signer, ok := selected.Backend().(key.Signer)
	if !ok {
		return key.KeyDescriptor{}, nil, fmt.Errorf("keystore: backend for key %q does not implement signing", selected.ID())
	}
	descriptor := selected.Descriptor(algorithm)
	var used atomic.Bool
	sign := func(message []byte) ([]byte, error) {
		if !used.CompareAndSwap(false, true) {
			return nil, fmt.Errorf("keystore: signer for key %q has already been used", selected.ID())
		}
		signature, err := signer.Sign(ctx, algorithm, message)
		if err != nil {
			return nil, fmt.Errorf("keystore: sign with key %q and algorithm %q: %w", selected.ID(), algorithm, err)
		}
		return signature, nil
	}
	return descriptor, sign, nil
}

// Verify selects a key and verifies signature. Active and passive
// keys are eligible for verification.
func (k *store) Verify(ctx context.Context, message, signature []byte, options ...VerifyOption) error {
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

	verifier, ok := selected.Backend().(key.Verifier)
	if !ok {
		return fmt.Errorf("keystore: backend for key %q does not implement signature verification", selected.ID())
	}
	if err := verifier.Verify(ctx, algorithm, signature, message); err != nil {
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
	selector key.Selector,
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
	use := key.KeyUseSigning
	if operation == key.KeyOpEncrypt || operation == key.KeyOpDecrypt {
		use = key.KeyUseEncryption
	}
	for _, algorithm := range algorithms {
		eligible := selector.And(
			key.WithoutStatus(key.KeyStatusDisabled),
			key.WithValidityAt(now),
			key.WithCapability(key.Capability{
				Use:       use,
				Operation: operation,
				Algorithm: algorithm,
			}),
		)
		if operation == key.KeyOpSign || operation == key.KeyOpEncrypt {
			eligible = eligible.And(key.WithoutStatus(key.KeyStatusPassive))
		}
		var matches []key.Key
		for _, candidate := range candidates {
			if eligible.Matches(candidate) {
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
