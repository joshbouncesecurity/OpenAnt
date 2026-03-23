"""
Central model configuration.

All Claude model IDs are defined here. Change these to update which models
are used across the entire pipeline.
"""

# Primary model — high capability, used for critical analysis and verification
MODEL_PRIMARY = "claude-opus-4-6"

# Auxiliary model — cost-effective, used for enhancement, consistency, context
MODEL_AUXILIARY = "claude-sonnet-4-6"

# Default fallback when no model is specified
MODEL_DEFAULT = MODEL_PRIMARY
