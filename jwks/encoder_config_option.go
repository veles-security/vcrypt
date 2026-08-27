package jwks

// WithEncoderRuntimeOptions configures encoder options that are applied to
// every Encode call before its per-call options.
func WithEncoderRuntimeOptions(options ...EncoderOption) EncoderConfigOption {
	return func(encoder *Encoder) error {
		encoder.runtimeOptions = append([]EncoderOption(nil), options...)
		return nil
	}
}
