package jwks

// WithDecoderRuntimeOptions configures decoder options that are applied to
// every Decode call before its per-call options.
func WithDecoderRuntimeOptions(options ...DecoderOption) DecoderConfigOption {
	return func(decoder *Decoder) error {
		decoder.runtimeOptions = append([]DecoderOption(nil), options...)
		return nil
	}
}
