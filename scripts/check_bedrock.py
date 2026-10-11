"""Run on the EC2 (or inside the defender container) to confirm Bedrock works through the IAM role.

    python scripts/check_bedrock.py <model-id> [region]
"""
import sys

sys.path.insert(0, ".")
from reliability.loop import bedrock_call_llm

model = sys.argv[1]
region = sys.argv[2] if len(sys.argv) > 2 else "us-west-2"
print(bedrock_call_llm(model, region, max_tokens=20)("Reply with one word.", "Say OK."))
