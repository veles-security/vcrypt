package keystore

import (
	"context"
	"fmt"
	"sort"
	"strings"
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
	request, err := applyRuntimeOptions(options)
	if err != nil {
		return SignResult{}, fmt.Errorf("vcrypt: apply signing option: %w", err)
	}
	if len(request.Algorithms) == 0 {
		return SignResult{}, fmt.Errorf("vcrypt: signing algorithms are empty")
	}

	selected, algorithm, err := k.selectKey(ctx, key.KeyOpSign, request.Owner, request.Source, request.Kid, request.Algorithms)
	if err != nil {
		return SignResult{}, err
	}

	signature, err := selected.Backend().Sign(ctx, algorithm, message)
	if err != nil {
		return SignResult{}, fmt.Errorf("vcrypt: sign with key %q and algorithm %q: %w", selected.ID(), algorithm, err)
	}

	return SignResult{
		Signature: signature,
		Key:       selected.Descriptor(algorithm),
	}, nil
}

// VerifySignature selects a key and verifies signature. Active and passive
// keys are eligible for verification.
func (k *store) VerifySignature(ctx context.Context, message, signature []byte, options ...VerifyOption) error {
	request, err := applyRuntimeOptions(options)
	if err != nil {
		return fmt.Errorf("vcrypt: apply verification option: %w", err)
	}
	if strings.TrimSpace(request.Kid) == "" {
		return fmt.Errorf("vcrypt: verification key ID is empty")
	}
	if len(request.Algorithms) == 0 {
		return fmt.Errorf("vcrypt: verification algorithm is empty")
	}

	selected, algorithm, err := k.selectKey(
		ctx,
		key.KeyOpVerify,
		request.Owner,
		request.Source,
		request.Kid,
		request.Algorithms,
	)
	if err != nil {
		return err
	}

	if err := selected.Backend().VerifySignature(ctx, algorithm, signature, message); err != nil {
		return fmt.Errorf("vcrypt: verify with key %q and algorithm %q: %w", selected.ID(), algorithm, err)
	}
	return nil
}

func (k *store) selectKey(
	ctx context.Context,
	operation key.KeyOperation,
	owner string,
	source string,
	id string,
	algorithms []key.KeyAlg,
) (key.Key, key.KeyAlg, error) {
	if k == nil {
		return key.Key{}, "", fmt.Errorf("keystore: not initialized")
	}

	predicates := make([]KeyQueryPredicate, 0, 3)
	if id != "" {
		predicates = append(predicates, WithID(id))
	}
	if owner != "" {
		predicates = append(predicates, WithOwner(owner))
	}
	if source != "" {
		predicates = append(predicates, WithSource(source))
	}
	candidates, err := k.repository.Find(ctx, predicates...)
	if err != nil {
		return key.Key{}, "", fmt.Errorf("vcrypt: find key: %w", err)
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
			return key.Key{}, "", fmt.Errorf("vcrypt: multiple keys with priority %d support operation %q and algorithm %q", matches[0].Priority(), operation, algorithm)
		}
		return matches[0], algorithm, nil
	}

	return key.Key{}, "", fmt.Errorf("vcrypt: no eligible key supports operation %q and algorithms %v", operation, algorithms)
}

func (k *store) eligible(candidate key.Key, operation key.KeyOperation, algorithm key.KeyAlg, now time.Time) bool {
	if candidate.Backend() == nil {
		return false
	}
	if operation == key.KeyOpSign {
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
	if !candidate.Backend().Supports(key.KeyUseSigning, operation, algorithm) {
		return false
	}

	restrictions := candidate.Restrictions()
	if len(restrictions) == 0 {
		return true
	}
	for _, restriction := range restrictions {
		if restriction.Use == key.KeyUseSigning && restriction.Operation == operation && restriction.Algorithm == algorithm {
			return true
		}
	}
	return false
}
