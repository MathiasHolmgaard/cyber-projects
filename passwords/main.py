import hashlib
import httpx
from fastapi import FastAPI
from pydantic import BaseModel, Field, SecretStr
from pydantic_settings import BaseSettings
from zxcvbn import zxcvbn
from argon2 import PasswordHasher

class Settings(BaseSettings):
    # HIBP Pwned Passwords API doesn't strictly need a key for the k-Anonymity endpoint,
    # but we support it in case of rate limiting or premium subscriptions.
    hibp_api_key: str | None = None
    
    class Config:
        env_file = ".env"

settings = Settings()
app = FastAPI(title="Password Strength Analyzer (NIST SP 800-63b Compliant)")

# Argon2id hasher configuration
# Recommended by OWASP and NIST for password storage
ph = PasswordHasher(
    time_cost=3,          # Number of iterations
    memory_cost=65536,    # Memory usage in KB (64 MB)
    parallelism=4,        # Threads
    hash_len=32,          # Output length
    salt_len=16           # Salt length
)

class PasswordRequest(BaseModel):
    # Use SecretStr so plain text doesn't accidentally leak into system logs if the model is dumped
    password: SecretStr = Field(..., description="The password to analyze or hash")

class AnalyzeResponse(BaseModel):
    is_valid: bool
    length: int
    entropy_score: int
    estimated_guesses: float
    is_pwned: bool
    pwned_count: int
    feedback_warning: str
    feedback_suggestions: list[str]

class HashResponse(BaseModel):
    argon2id_hash: str

async def check_hibp(password: str) -> int:
    """
    Checks Have I Been Pwned using the k-Anonymity model.
    Only the first 5 characters of the SHA-1 hash are sent to the API.
    """
    sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1_hash[:5], sha1_hash[5:]
    
    headers = {"User-Agent": "Antigravity-Password-Analyzer"}
    if settings.hibp_api_key:
        headers["hibp-api-key"] = settings.hibp_api_key

    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(
                f"https://api.pwnedpasswords.com/range/{prefix}",
                headers=headers,
                timeout=5.0
            )
            response.raise_for_status()
        except httpx.RequestError as e:
            print(f"Error communicating with HIBP API: {e}")
            return 0
            
    # Parse the response and look for the suffix
    for line in response.text.splitlines():
        if line.startswith(suffix):
            count = int(line.split(':')[1])
            return count
    return 0

@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze_password(req: PasswordRequest):
    pwd = req.password.get_secret_value()
    length = len(pwd)
    
    # Run zxcvbn to evaluate entropy and commonly used password patterns
    results = zxcvbn(pwd)
    score = results['score'] # Ranges from 0 (weak) to 4 (strong)
    guesses = results['guesses']
    feedback = results['feedback']
    warning = feedback.get('warning', '')
    suggestions = feedback.get('suggestions', [])
    
    # HIBP check using k-Anonymity
    pwned_count = await check_hibp(pwd)
    
    # NIST SP 800-63b rules:
    # - Length minimum 8.
    # - Must not be found in data breaches (commonly used/pwned).
    is_valid = True
    
    if length < 8:
        is_valid = False
        suggestions.append("Password must be at least 8 characters long (NIST SP 800-63b).")
        
    if pwned_count > 0:
        is_valid = False
        warning = "This password has appeared in a data breach. Do not use it."
        
    # We encourage strength even if complexity rules (e.g. required special character) are dropped.
    if score < 3:
        is_valid = False
        if not warning:
            warning = "Password entropy is too low. It is too easy to guess."
            
    return AnalyzeResponse(
        is_valid=is_valid,
        length=length,
        entropy_score=score,
        estimated_guesses=guesses,
        is_pwned=(pwned_count > 0),
        pwned_count=pwned_count,
        feedback_warning=warning,
        feedback_suggestions=suggestions
    )

@app.post("/hash", response_model=HashResponse)
async def hash_password(req: PasswordRequest):
    """
    Demonstrates correct hashing of a verified password using Argon2id.
    """
    pwd = req.password.get_secret_value()
    
    # Secure hashing:
    # 1. Salt is auto-generated per call by argon2-cffi.
    # 2. Time, memory, parallel costs are configured according to modern standards.
    hashed = ph.hash(pwd)
    
    return HashResponse(argon2id_hash=hashed)
